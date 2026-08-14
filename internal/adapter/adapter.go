package adapter

import "context"

// SMSSender 短信发送适配器。
type SMSSender interface {
	SendOTP(ctx context.Context, phone, code, scene string) error
}

// EmailSender 邮件发送适配器。
type EmailSender interface {
	SendOTP(ctx context.Context, email, code, scene string) error
}

// Mailer 通用邮件（登录通知等）。
type Mailer interface {
	SendMail(ctx context.Context, to, subject, body string) error
}

// SMSNotifier 非 OTP 短信通知。
type SMSNotifier interface {
	SendText(ctx context.Context, phone, content string) error
}

// OAuthUserInfo 第三方用户信息。
type OAuthUserInfo struct {
	Subject string
	Name    string
	Avatar  string
	Email   string
	RawJSON string
}

// OAuthProvider 第三方 OAuth 适配器。
type OAuthProvider interface {
	Name() string
	AuthURL(state, redirectURI, codeChallenge string) string
	Exchange(ctx context.Context, code, redirectURI, codeVerifier string) (*OAuthUserInfo, error)
}
