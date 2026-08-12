package captcha

import (
	"context"
	"strings"

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
