package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/webhook"
)

func (s *AdminService) SetWebhookBus(bus *webhook.Bus) { s.webhookBus = bus }

type UpsertWebhookRequest struct {
	Name        string   `json:"name" binding:"required"`
	URL         string   `json:"url" binding:"required"`
	Secret      string   `json:"secret"`
	Events      []string `json:"events"`
	Enabled     *bool    `json:"enabled"`
	TimeoutSec  int      `json:"timeout_sec"`
	MaxAttempts int      `json:"max_attempts"`
}

type WebhookView struct {
	ID          uint64   `json:"id"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	SecretHint  string   `json:"secret_hint"`
	Events      []string `json:"events"`
	Enabled     bool     `json:"enabled"`
	TimeoutSec  int      `json:"timeout_sec"`
	MaxAttempts int      `json:"max_attempts"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

func (s *AdminService) ListWebhooks(ctx context.Context) ([]WebhookView, error) {
	var list []model.WebhookEndpoint
	if err := s.repos.DB.WithContext(ctx).Order("id desc").Find(&list).Error; err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询 webhook 失败", err)
	}
	out := make([]WebhookView, 0, len(list))
	for _, w := range list {
		out = append(out, toWebhookView(w))
	}
	return out, nil
}

func (s *AdminService) CreateWebhook(ctx context.Context, req UpsertWebhookRequest, actor string) (*WebhookView, error) {
	secret := strings.TrimSpace(req.Secret)
	if secret == "" {
		secret = randomSecret(24)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	row := model.WebhookEndpoint{
		Name: req.Name, URL: strings.TrimSpace(req.URL), Secret: secret,
		Events: model.StringList(req.Events), Enabled: enabled,
		TimeoutSec: req.TimeoutSec, MaxAttempts: req.MaxAttempts,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if row.TimeoutSec <= 0 {
		row.TimeoutSec = 5
	}
	if row.MaxAttempts <= 0 {
		row.MaxAttempts = 5
	}
	if err := s.repos.DB.WithContext(ctx).Create(&row).Error; err != nil {
		return nil, errcode.Wrap(errcode.Internal, "创建 webhook 失败", err)
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_webhook_create", Success: true,
		Detail: row.Name + " " + row.URL, CreatedAt: time.Now(),
	})
	v := toWebhookView(row)
	return &v, nil
}

func (s *AdminService) UpdateWebhook(ctx context.Context, id uint64, req UpsertWebhookRequest, actor string) (*WebhookView, error) {
	var row model.WebhookEndpoint
	if err := s.repos.DB.WithContext(ctx).First(&row, id).Error; err != nil {
		return nil, errcode.New(errcode.NotFound, "webhook 不存在")
	}
	row.Name = req.Name
	row.URL = strings.TrimSpace(req.URL)
	if strings.TrimSpace(req.Secret) != "" {
		row.Secret = strings.TrimSpace(req.Secret)
	}
	row.Events = model.StringList(req.Events)
	if req.Enabled != nil {
		row.Enabled = *req.Enabled
	}
	if req.TimeoutSec > 0 {
		row.TimeoutSec = req.TimeoutSec
	}
	if req.MaxAttempts > 0 {
		row.MaxAttempts = req.MaxAttempts
	}
	row.UpdatedAt = time.Now()
	if err := s.repos.DB.WithContext(ctx).Save(&row).Error; err != nil {
		return nil, errcode.Wrap(errcode.Internal, "更新 webhook 失败", err)
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_webhook_update", Success: true,
		Detail: row.Name, CreatedAt: time.Now(),
	})
	v := toWebhookView(row)
	return &v, nil
}

func (s *AdminService) DeleteWebhook(ctx context.Context, id uint64, actor string) error {
	res := s.repos.DB.WithContext(ctx).Delete(&model.WebhookEndpoint{}, id)
	if res.Error != nil {
		return errcode.Wrap(errcode.Internal, "删除失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return errcode.New(errcode.NotFound, "webhook 不存在")
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_webhook_delete", Success: true,
		Detail: "id=" + itoaU64(id), CreatedAt: time.Now(),
	})
	return nil
}

type WebhookDeliveryView struct {
	ID             uint64 `json:"id"`
	EndpointID     uint64 `json:"endpoint_id"`
	EventID        string `json:"event_id"`
	EventType      string `json:"event_type"`
	Status         string `json:"status"`
	Attempts       int    `json:"attempts"`
	LastHTTPStatus int    `json:"last_http_status"`
	LastError      string `json:"last_error,omitempty"`
	NextRetryAt    string `json:"next_retry_at,omitempty"`
	DeliveredAt    string `json:"delivered_at,omitempty"`
	CreatedAt      string `json:"created_at"`
}

func (s *AdminService) ListWebhookDeliveries(ctx context.Context, endpointID uint64, status string, limit, offset int) ([]WebhookDeliveryView, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	q := s.repos.DB.WithContext(ctx).Model(&model.WebhookDelivery{})
	if endpointID > 0 {
		q = q.Where("endpoint_id = ?", endpointID)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var total int64
	_ = q.Count(&total)
	var list []model.WebhookDelivery
	if err := q.Order("id desc").Limit(limit).Offset(offset).Find(&list).Error; err != nil {
		return nil, 0, errcode.Wrap(errcode.Internal, "查询投递失败", err)
	}
	out := make([]WebhookDeliveryView, 0, len(list))
	for _, d := range list {
		v := WebhookDeliveryView{
			ID: d.ID, EndpointID: d.EndpointID, EventID: d.EventID, EventType: d.EventType,
			Status: d.Status, Attempts: d.Attempts, LastHTTPStatus: d.LastStatus, LastError: d.LastError,
			CreatedAt: d.CreatedAt.Format(time.RFC3339),
		}
		if d.NextRetryAt != nil {
			v.NextRetryAt = d.NextRetryAt.Format(time.RFC3339)
		}
		if d.DeliveredAt != nil {
			v.DeliveredAt = d.DeliveredAt.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	return out, total, nil
}

func toWebhookView(w model.WebhookEndpoint) WebhookView {
	hint := w.Secret
	if len(hint) > 6 {
		hint = hint[:3] + "***" + hint[len(hint)-2:]
	}
	ev := []string(w.Events)
	if ev == nil {
		ev = []string{}
	}
	return WebhookView{
		ID: w.ID, Name: w.Name, URL: w.URL, SecretHint: hint, Events: ev,
		Enabled: w.Enabled, TimeoutSec: w.TimeoutSec, MaxAttempts: w.MaxAttempts,
		CreatedAt: w.CreatedAt.Format(time.RFC3339), UpdatedAt: w.UpdatedAt.Format(time.RFC3339),
	}
}

func randomSecret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func itoaU64(v uint64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}
