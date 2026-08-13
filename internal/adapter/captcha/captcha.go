package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
)

// Verifier 人机验证适配器。
type Verifier interface {
	Verify(ctx context.Context, token, ip string) error
}

// MockVerifier 开发用：enabled 时要求 token 非空且不等于 "fail"。
type MockVerifier struct {
	Enabled bool
}

func NewMock(enabled bool) *MockVerifier {
	return &MockVerifier{Enabled: enabled}
}

func (m *MockVerifier) Verify(ctx context.Context, token, ip string) error {
	if !m.Enabled {
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.EqualFold(token, "fail") {
		return errcode.New(errcode.BadRequest, "人机验证失败")
	}
	return nil
}

// Noop 始终通过。
type Noop struct{}

func (Noop) Verify(ctx context.Context, token, ip string) error { return nil }

// NewFromConfig 按配置创建 Verifier。
func NewFromConfig(cfg config.CaptchaConfig) Verifier {
	if !cfg.Enabled {
		return Noop{}
	}
	switch strings.ToLower(cfg.Provider) {
	case "turnstile":
		return NewTurnstile(cfg.SecretKey)
	case "recaptcha":
		return NewRecaptcha(cfg.SecretKey)
	default:
		return NewMock(true)
	}
}

type Turnstile struct {
	secret string
	client *http.Client
}

func NewTurnstile(secret string) *Turnstile {
	return &Turnstile{secret: secret, client: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Turnstile) Verify(ctx context.Context, token, ip string) error {
	if strings.TrimSpace(t.secret) == "" {
		return errcode.New(errcode.Internal, "turnstile secret 未配置")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return errcode.New(errcode.BadRequest, "人机验证失败")
	}
	form := url.Values{}
	form.Set("secret", t.secret)
	form.Set("response", token)
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(form.Encode()))
	if err != nil {
		return errcode.Wrap(errcode.Internal, "人机验证请求失败", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.client.Do(req)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "人机验证请求失败", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return errcode.Wrap(errcode.Internal, "人机验证响应无效", err)
	}
	if !out.Success {
		return errcode.New(errcode.BadRequest, "人机验证失败")
	}
	return nil
}

type Recaptcha struct {
	secret string
	client *http.Client
}

func NewRecaptcha(secret string) *Recaptcha {
	return &Recaptcha{secret: secret, client: &http.Client{Timeout: 8 * time.Second}}
}

func (r *Recaptcha) Verify(ctx context.Context, token, ip string) error {
	if strings.TrimSpace(r.secret) == "" {
		return errcode.New(errcode.Internal, "recaptcha secret 未配置")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return errcode.New(errcode.BadRequest, "人机验证失败")
	}
	form := url.Values{}
	form.Set("secret", r.secret)
	form.Set("response", token)
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.google.com/recaptcha/api/siteverify", strings.NewReader(form.Encode()))
	if err != nil {
		return errcode.Wrap(errcode.Internal, "人机验证请求失败", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := r.client.Do(req)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "人机验证请求失败", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		Success bool    `json:"success"`
		Score   float64 `json:"score"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return errcode.Wrap(errcode.Internal, "人机验证响应无效", err)
	}
	if !out.Success {
		return errcode.New(errcode.BadRequest, "人机验证失败")
	}
	// v3 有 score 时做最低门槛；v2 无 score
	if out.Score > 0 && out.Score < 0.5 {
		return errcode.New(errcode.BadRequest, fmt.Sprintf("人机验证分数过低: %.2f", out.Score))
	}
	return nil
}
