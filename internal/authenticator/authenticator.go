package authenticator

import "context"

// IdentityPrincipal 认证器验证成功后解析出的身份主体。
type IdentityPrincipal struct {
	Type       string                 // phone|email|oauth
	Provider   string                 // oauth provider, optional
	Identifier string                 // normalized unique key
	Profile    map[string]interface{} `json:"profile,omitempty"`
	Verified   bool
}

type ChallengeRequest struct {
	ClientID     string
	TenantID     string
	Method       string
	Identity     string
	Scene        string
	CaptchaToken string
	IP           string
}

type ChallengeResult struct {
	ChallengeID  string `json:"challenge_id"`
	ExpireIn     int    `json:"expire_in"`
	ResendAfter  int    `json:"resend_after"`
	MaskedTarget string `json:"masked_target"`
}

type VerifyRequest struct {
	ClientID   string
	TenantID   string
	Method     string
	Identity   string
	Provider   string
	Credential map[string]string
	Scene      string
	IP         string
}

// Authenticator 登录方式插件接口。
type Authenticator interface {
	Method() string
	Challenge(ctx context.Context, req ChallengeRequest) (*ChallengeResult, error)
	Verify(ctx context.Context, req VerifyRequest) (*IdentityPrincipal, error)
}

// Registry 认证器注册表。
type Registry struct {
	items map[string]Authenticator
}

func NewRegistry(list ...Authenticator) *Registry {
	r := &Registry{items: map[string]Authenticator{}}
	for _, a := range list {
		r.items[a.Method()] = a
	}
	return r
}

func (r *Registry) Get(method string) (Authenticator, bool) {
	a, ok := r.items[method]
	return a, ok
}

func (r *Registry) Methods() []string {
	out := make([]string, 0, len(r.items))
	for k := range r.items {
		out = append(out, k)
	}
	return out
}
