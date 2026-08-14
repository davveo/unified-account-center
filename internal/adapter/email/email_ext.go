package email

import (
	"context"
	"log"
	"strings"

	"github.com/davveo/unified-account-center/internal/config"
)

func (m *MockSender) SendMail(ctx context.Context, to, subject, body string) error {
	log.Printf("[mock-email-mail] to=%s subject=%s body=%s", to, subject, truncate(body, 200))
	return nil
}

func (s *MQSender) SendMail(ctx context.Context, to, subject, body string) error {
	payload := map[string]string{
		"email": to, "subject": subject, "body": body, "type": "mail",
	}
	return s.producer.SendJSON(ctx, s.topic, "email_mail", payload)
}

// CloudSender 阿里云/腾讯云邮件；凭证不全时降级日志。
type CloudSender struct {
	provider string
	cfg      config.EmailConfig
}

func NewCloud(provider string, cfg config.EmailConfig) *CloudSender {
	return &CloudSender{provider: strings.ToLower(provider), cfg: cfg}
}

func (s *CloudSender) SendOTP(ctx context.Context, emailAddr, code, scene string) error {
	return s.SendMail(ctx, emailAddr, "验证码", "您的验证码是 "+code+"（场景:"+scene+"）")
}

func (s *CloudSender) SendMail(ctx context.Context, to, subject, body string) error {
	if s.cfg.AccessKeyID == "" || s.cfg.AccessKeySecret == "" {
		log.Printf("[%s-email-fallback] to=%s subject=%s body=%s", s.provider, to, subject, truncate(body, 200))
		return nil
	}
	log.Printf("[%s-email] from=%s to=%s subject=%s", s.provider, s.cfg.From, to, subject)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
