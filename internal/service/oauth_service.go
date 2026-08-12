package service

import (
	"context"
	"net/url"

	"github.com/davveo/unified-account-center/internal/adapter/oauth"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/repository"
)

type OAuthService struct {
	repos    *repository.Repos
	registry *oauth.Registry
	auth     *AuthService
}

func NewOAuthService(repos *repository.Repos, registry *oauth.Registry, auth *AuthService) *OAuthService {
	return &OAuthService{repos: repos, registry: registry, auth: auth}
}

type OAuthStartResult struct {
	AuthorizeURL string `json:"authorize_url"`
	State        string `json:"state"`
}

func (s *OAuthService) Start(ctx context.Context, clientID, provider, redirectURI, state, codeChallenge string) (*OAuthStartResult, error) {
	app, err := s.auth.requireApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !contains(app.AllowedMethods, "oauth2") {
		return nil, errcode.New(errcode.ForbiddenApp, "应用未启用 oauth2")
	}
	if !redirectAllowed(app.RedirectURIs, redirectURI) {
		return nil, errcode.New(errcode.BadRequest, "redirect_uri 不在白名单")
	}
	p, ok := s.registry.Get(provider)
	if !ok {
		return nil, errcode.New(errcode.BadRequest, "不支持的 provider")
	}
	if state == "" {
		state = idgen.RandomHex(16)
	}
	return &OAuthStartResult{
		AuthorizeURL: p.AuthURL(state, redirectURI, codeChallenge),
		State:        state,
	}, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func redirectAllowed(list []string, redirectURI string) bool {
	if redirectURI == "" {
		return false
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	for _, allowed := range list {
		a, err := url.Parse(allowed)
		if err != nil {
			continue
		}
		if a.Scheme == u.Scheme && a.Host == u.Host {
			// 允许同 host 下路径匹配或以白名单为前缀
			if u.Path == a.Path || stringsHasPrefix(u.String(), allowed) {
				return true
			}
		}
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
