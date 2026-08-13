package service

import (
	"context"
	"time"

	"github.com/davveo/unified-account-center/internal/adapter/oauth"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/repository"
)

const oauthStateTTL = 10 * time.Minute

type OAuthService struct {
	repos    *repository.Repos
	registry *oauth.Registry
	auth     *AuthService
	redis    *redisx.Client
}

func NewOAuthService(repos *repository.Repos, registry *oauth.Registry, auth *AuthService, rdb *redisx.Client) *OAuthService {
	return &OAuthService{repos: repos, registry: registry, auth: auth, redis: rdb}
}

type OAuthStartResult struct {
	AuthorizeURL string `json:"authorize_url"`
	State        string `json:"state"`
}

type OAuthStatePayload struct {
	ClientID      string `json:"client_id"`
	Provider      string `json:"provider"`
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge,omitempty"`
	BindUserID    string `json:"bind_user_id,omitempty"` // 已登录绑定场景
}

func (s *OAuthService) Start(ctx context.Context, clientID, provider, redirectURI, state, codeChallenge, bindUserID string) (*OAuthStartResult, error) {
	app, err := s.auth.requireApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !contains(app.AllowedMethods, "oauth2") {
		return nil, errcode.New(errcode.ForbiddenApp, "应用未启用 oauth2")
	}
	if len(app.OAuthProviders) > 0 && !contains(app.OAuthProviders, provider) {
		return nil, errcode.New(errcode.ForbiddenApp, "应用未启用该 OAuth Provider")
	}
	if !redirectAllowed(app.RedirectURIs, redirectURI) {
		return nil, errcode.New(errcode.BadRequest, "redirect_uri 不在白名单")
	}
	if app.RequirePKCE && codeChallenge == "" {
		return nil, errcode.New(errcode.BadRequest, "应用要求 PKCE，缺少 code_challenge")
	}
	p, ok := s.registry.Get(provider)
	if !ok {
		return nil, errcode.New(errcode.BadRequest, "不支持的 provider")
	}
	if state == "" {
		state = idgen.RandomHex(16)
	}
	payload := OAuthStatePayload{
		ClientID:      clientID,
		Provider:      provider,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		BindUserID:    bindUserID,
	}
	if err := s.redis.SetJSON(ctx, oauthStateKey(state), payload, oauthStateTTL); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "保存 OAuth state 失败", err)
	}
	return &OAuthStartResult{
		AuthorizeURL: p.AuthURL(state, redirectURI, codeChallenge),
		State:        state,
	}, nil
}

// ConsumeState 一次性校验并消费 state。
func (s *OAuthService) ConsumeState(ctx context.Context, clientID, provider, state, redirectURI string) (*OAuthStatePayload, error) {
	if state == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 state")
	}
	var payload OAuthStatePayload
	ok, err := s.redis.GetDelJSON(ctx, oauthStateKey(state), &payload)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "读取 OAuth state 失败", err)
	}
	if !ok {
		return nil, errcode.New(errcode.InvalidCred, "state 无效或已过期")
	}
	if payload.ClientID != clientID {
		return nil, errcode.New(errcode.InvalidCred, "state 与应用不匹配")
	}
	if payload.Provider != provider {
		return nil, errcode.New(errcode.InvalidCred, "state 与 provider 不匹配")
	}
	if payload.RedirectURI != redirectURI {
		return nil, errcode.New(errcode.InvalidCred, "redirect_uri 与授权时不一致")
	}
	return &payload, nil
}

func oauthStateKey(state string) string {
	return "uac:oauth:state:" + state
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// redirectAllowed 仅允许精确匹配白名单条目。
func redirectAllowed(list []string, redirectURI string) bool {
	if redirectURI == "" {
		return false
	}
	for _, allowed := range list {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}
