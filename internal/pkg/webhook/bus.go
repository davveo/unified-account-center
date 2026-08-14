package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"gorm.io/gorm"
)

// Bus 出站事件总线：入队 → 异步投递 → 重试 → 死信。
type Bus struct {
	db     *gorm.DB
	client *http.Client
	mu     sync.Mutex
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewBus(db *gorm.DB) *Bus {
	return &Bus{
		db:     db,
		client: &http.Client{Timeout: 10 * time.Second},
		stopCh: make(chan struct{}),
	}
}

func (b *Bus) Start() {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-b.stopCh:
				return
			case <-t.C:
				b.flushRetries(context.Background())
			}
		}
	}()
}

func (b *Bus) Stop() {
	close(b.stopCh)
	b.wg.Wait()
}

type Event struct {
	Type      string                 `json:"type"`
	ID        string                 `json:"id"`
	Timestamp string                 `json:"timestamp"`
	TenantID  string                 `json:"tenant_id,omitempty"`
	ClientID  string                 `json:"client_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

func (b *Bus) Emit(ctx context.Context, eventType, tenantID, clientID, userID string, data map[string]interface{}) {
	if b == nil || b.db == nil {
		return
	}
	ev := Event{
		Type:      eventType,
		ID:        idgen.New("evt"),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		TenantID:  tenantID,
		ClientID:  clientID,
		UserID:    userID,
		Data:      data,
	}
	payload, _ := json.Marshal(ev)

	var endpoints []model.WebhookEndpoint
	if err := b.db.WithContext(ctx).Where("enabled = ?", true).Find(&endpoints).Error; err != nil || len(endpoints) == 0 {
		return
	}
	now := time.Now()
	for _, ep := range endpoints {
		if !matchEvent(ep.Events, eventType) {
			continue
		}
		d := model.WebhookDelivery{
			EndpointID:  ep.ID,
			EventID:     ev.ID,
			EventType:   eventType,
			PayloadJSON: string(payload),
			Status:      model.WebhookDeliveryPending,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := b.db.WithContext(ctx).Create(&d).Error; err != nil {
			continue
		}
		epCopy := ep
		deliveryID := d.ID
		go b.deliver(epCopy, deliveryID, string(payload), ev.ID, eventType)
	}
}

func matchEvent(events model.StringList, typ string) bool {
	if len(events) == 0 {
		return true
	}
	for _, e := range events {
		if e == typ || e == "*" {
			return true
		}
	}
	return false
}

func Sign(secret, timestamp, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "." + body))
	return hex.EncodeToString(mac.Sum(nil))
}

func (b *Bus) deliver(ep model.WebhookEndpoint, deliveryID uint64, body, eventID, eventType string) {
	timeout := time.Duration(ep.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	maxAttempts := ep.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := Sign(ep.Secret, ts, body)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader([]byte(body)))
	if err != nil {
		b.markFail(deliveryID, 0, err.Error(), maxAttempts)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UAC-Event", eventType)
	req.Header.Set("X-UAC-Delivery", eventID)
	req.Header.Set("X-UAC-Timestamp", ts)
	req.Header.Set("X-UAC-Signature", "sha256="+sig)
	req.Header.Set("User-Agent", "unified-account-center-webhook/1.0")

	cli := b.client
	if ep.TimeoutSec > 0 {
		cli = &http.Client{Timeout: timeout}
	}
	resp, err := cli.Do(req)
	if err != nil {
		b.markFail(deliveryID, 0, err.Error(), maxAttempts)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		now := time.Now()
		_ = b.db.Model(&model.WebhookDelivery{}).Where("id = ?", deliveryID).Updates(map[string]interface{}{
			"status": model.WebhookDeliverySuccess, "attempts": gorm.Expr("attempts + 1"),
			"last_http_status": resp.StatusCode, "last_error": "", "delivered_at": now, "updated_at": now,
		}).Error
		return
	}
	b.markFail(deliveryID, resp.StatusCode, fmt.Sprintf("http %d", resp.StatusCode), maxAttempts)
}

func (b *Bus) markFail(deliveryID uint64, httpStatus int, errMsg string, maxAttempts int) {
	var d model.WebhookDelivery
	if err := b.db.First(&d, deliveryID).Error; err != nil {
		return
	}
	attempts := d.Attempts + 1
	now := time.Now()
	updates := map[string]interface{}{
		"attempts": attempts, "last_http_status": httpStatus, "last_error": truncate(errMsg, 500), "updated_at": now,
	}
	if attempts >= maxAttempts {
		updates["status"] = model.WebhookDeliveryDead
		updates["next_retry_at"] = nil
		log.Printf(`{"msg":"webhook_dead","delivery_id":%d,"event":"%s","error":"%s"}`, deliveryID, d.EventType, errMsg)
	} else {
		backoff := time.Duration(1<<uint(min(attempts, 5))) * time.Second
		next := now.Add(backoff)
		updates["status"] = model.WebhookDeliveryRetry
		updates["next_retry_at"] = next
	}
	_ = b.db.Model(&model.WebhookDelivery{}).Where("id = ?", deliveryID).Updates(updates).Error
}

func (b *Bus) flushRetries(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	var list []model.WebhookDelivery
	err := b.db.WithContext(ctx).
		Where("status = ? AND next_retry_at IS NOT NULL AND next_retry_at <= ?", model.WebhookDeliveryRetry, now).
		Order("id asc").Limit(50).Find(&list).Error
	if err != nil || len(list) == 0 {
		return
	}
	for _, d := range list {
		var ep model.WebhookEndpoint
		if err := b.db.First(&ep, d.EndpointID).Error; err != nil || !ep.Enabled {
			_ = b.db.Model(&d).Updates(map[string]interface{}{
				"status": model.WebhookDeliveryDead, "last_error": "endpoint missing/disabled", "updated_at": now,
			}).Error
			continue
		}
		go b.deliver(ep, d.ID, d.PayloadJSON, d.EventID, d.EventType)
	}
}

// TestEndpoint 向指定端点发送试投递事件。
func (b *Bus) TestEndpoint(ctx context.Context, endpointID uint64) (uint64, error) {
	if b == nil || b.db == nil {
		return 0, fmt.Errorf("webhook bus unavailable")
	}
	var ep model.WebhookEndpoint
	if err := b.db.WithContext(ctx).First(&ep, endpointID).Error; err != nil {
		return 0, err
	}
	ev := Event{
		Type: "webhook.test", ID: idgen.New("evt"),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      map[string]interface{}{"ping": true},
	}
	payload, _ := json.Marshal(ev)
	now := time.Now()
	d := model.WebhookDelivery{
		EndpointID: ep.ID, EventID: ev.ID, EventType: ev.Type,
		PayloadJSON: string(payload), Status: model.WebhookDeliveryPending,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := b.db.WithContext(ctx).Create(&d).Error; err != nil {
		return 0, err
	}
	go b.deliver(ep, d.ID, string(payload), ev.ID, ev.Type)
	return d.ID, nil
}

// ReplayDelivery 重放一条投递（含死信）。
func (b *Bus) ReplayDelivery(ctx context.Context, deliveryID uint64) (uint64, error) {
	if b == nil || b.db == nil {
		return 0, fmt.Errorf("webhook bus unavailable")
	}
	var old model.WebhookDelivery
	if err := b.db.WithContext(ctx).First(&old, deliveryID).Error; err != nil {
		return 0, err
	}
	var ep model.WebhookEndpoint
	if err := b.db.WithContext(ctx).First(&ep, old.EndpointID).Error; err != nil {
		return 0, err
	}
	now := time.Now()
	d := model.WebhookDelivery{
		EndpointID: ep.ID, EventID: old.EventID + "-replay", EventType: old.EventType,
		PayloadJSON: old.PayloadJSON, Status: model.WebhookDeliveryPending,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := b.db.WithContext(ctx).Create(&d).Error; err != nil {
		return 0, err
	}
	go b.deliver(ep, d.ID, old.PayloadJSON, d.EventID, d.EventType)
	return d.ID, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
