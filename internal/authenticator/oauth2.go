package authenticator

import (
	"context"

	"github.com/davveo/unified-account-center/internal/adapter/oauth"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
)

type OAuth2Auth struct {
	registry *oauth.Registry
}

func NewOAuth2(registry *oauth.Registry) *OAuth2Auth {
	return &OAuth2Auth{registry: registry}
}

func (a *OAuth2Auth) Method() string { return model.MethodOAuth2 }

func (a *OAuth2Auth) Challenge(ctx context.Context, req ChallengeRequest) (*ChallengeResult, error) {
	return nil, errcode.New(errcode.BadRequest, "oauth2 请使用 /oauth/{provider}/start")
}

func (a *OAuth2Auth) Verify(ctx context.Context, req VerifyRequest) (*IdentityPrincipal, error) {
	providerName := req.Provider
	if providerName == "" {
		providerName = req.Credential["provider"]
	}
	if providerName == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 provider")
	}
	provider, ok := a.registry.Get(providerName)
	if !ok {
		return nil, errcode.New(errcode.BadRequest, "不支持的 OAuth Provider")
	}
	code := req.Credential["code"]
	redirectURI := req.Credential["redirect_uri"]
	verifier := req.Credential["code_verifier"]
	if code == "" || redirectURI == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 code 或 redirect_uri")
	}
	info, err := provider.Exchange(ctx, code, redirectURI, verifier)
	if err != nil {
		return nil, errcode.Wrap(errcode.InvalidCred, "OAuth 换取身份失败", err)
	}
	profile := map[string]interface{}{
		"name":   info.Name,
		"avatar": info.Avatar,
		"email":  info.Email,
	}
	return &IdentityPrincipal{
		Type:       model.IdentityOAuth,
		Provider:   providerName,
		Identifier: info.Subject,
		Verified:   true,
		Profile:    profile,
	}, nil
}
