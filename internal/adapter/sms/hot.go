package sms

import (
	"context"
	"sync/atomic"

	"github.com/davveo/unified-account-center/internal/adapter"
)

// HotSender 可热切换底层 SMS 实现，无需重启 OTP authenticator。
type HotSender struct {
	cur atomic.Value // adapter.SMSSender
}

func NewHot(initial adapter.SMSSender) *HotSender {
	h := &HotSender{}
	if initial == nil {
		initial = NewMock()
	}
	h.cur.Store(initial)
	return h
}

func (h *HotSender) SendOTP(ctx context.Context, phone, code, scene string) error {
	s, _ := h.cur.Load().(adapter.SMSSender)
	if s == nil {
		return NewMock().SendOTP(ctx, phone, code, scene)
	}
	return s.SendOTP(ctx, phone, code, scene)
}

func (h *HotSender) Swap(next adapter.SMSSender) {
	if next == nil {
		next = NewMock()
	}
	h.cur.Store(next)
}

func (h *HotSender) Current() adapter.SMSSender {
	s, _ := h.cur.Load().(adapter.SMSSender)
	return s
}
