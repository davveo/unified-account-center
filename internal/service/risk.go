package service

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
)

func (s *AuthService) assertNotLocked(ctx context.Context, identityKey, ip string) error {
	if identityKey != "" {
		var locked bool
		ok, _ := s.redis.GetJSON(ctx, riskLockKey("id", identityKey), &locked)
		if ok && locked {
			return errcode.New(errcode.RateLimited, "账号已暂时锁定，请稍后再试")
		}
	}
	if ip != "" {
		var locked bool
		ok, _ := s.redis.GetJSON(ctx, riskLockKey("ip", ip), &locked)
		if ok && locked {
			return errcode.New(errcode.RateLimited, "网络已暂时锁定，请稍后再试")
		}
	}
	return nil
}

func (s *AuthService) noteLoginFailure(ctx context.Context, identityKey, ip string) {
	win := time.Duration(s.cfg.Risk.LockWindowSec) * time.Second
	limit := s.cfg.Risk.LockAfterFailures
	lockFor := time.Duration(s.cfg.Risk.LockDurationSec) * time.Second
	if limit <= 0 {
		limit = 10
	}
	if win <= 0 {
		win = 15 * time.Minute
	}
	if lockFor <= 0 {
		lockFor = 15 * time.Minute
	}
	check := func(kind, key string) {
		if key == "" {
			return
		}
		ok, _, err := s.redis.Allow(ctx, "uac:risk:fail:"+kind+":"+key, limit, win)
		if err == nil && !ok {
			_ = s.redis.SetJSON(ctx, riskLockKey(kind, key), true, lockFor)
			s.fireRiskAlert(ctx, "login_lock", map[string]interface{}{
				"kind": kind, "key": key, "lock_seconds": int(lockFor.Seconds()),
			})
		}
	}
	check("id", identityKey)
	check("ip", ip)
}

func (s *AuthService) clearLoginFailures(ctx context.Context, identityKey, ip string) {
	// 锁定用独立 key；失败计数随窗口自然过期，这里只清锁
	if identityKey != "" {
		_ = s.redis.Del(ctx, riskLockKey("id", identityKey))
	}
	if ip != "" {
		_ = s.redis.Del(ctx, riskLockKey("ip", ip))
	}
}

func riskLockKey(kind, key string) string { return "uac:risk:lock:" + kind + ":" + key }

func (s *AuthService) isNewDevice(ctx context.Context, userID, clientID, deviceID string) bool {
	if deviceID == "" {
		return true
	}
	d, err := s.repos.Device.Find(ctx, userID, clientID, deviceID)
	return err != nil || d == nil
}

func (s *AuthService) rememberDevice(ctx context.Context, userID, clientID string, client ClientInfo, meta RequestMeta) error {
	if client.DeviceID == "" {
		return nil
	}
	return s.repos.Device.Upsert(ctx, &model.KnownDevice{
		UserID: userID, ClientID: clientID, DeviceID: client.DeviceID,
		Fingerprint: client.Fingerprint, IP: meta.IP, UA: meta.UA,
	})
}

func (s *AuthService) fireRiskAlert(ctx context.Context, event string, payload map[string]interface{}) {
	url := s.cfg.Risk.AlertWebhookURL
	if url == "" {
		return
	}
	body := map[string]interface{}{
		"event":     event,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"payload":   payload,
	}
	b, _ := json.Marshal(body)
	go func() {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		cli := &http.Client{Timeout: 5 * time.Second}
		resp, err := cli.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
}

func (s *AuthService) alertOTPLimit(ctx context.Context, kind, key string) {
	s.fireRiskAlert(ctx, "otp_daily_limit", map[string]interface{}{"kind": kind, "key": key})
}
