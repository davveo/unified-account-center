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

type oauthStatePayload struct {
	ClientID      string `json:"client_id"`
	Provider      string `json:"provider"`
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge,omitempty"`
}

func (s *OAuthService) Start(ctx context.Context, clientID, provider, redirectURI, state, codeChallenge string) (*OAuthStartResult, error) {
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
	p, ok := s.registry.Get(provider)
	if !ok {
		return nil, errcode.New(errcode.BadRequest, "不支持的 provider")
	}
	if state == "" {
		state = idgen.RandomHex(16)
	}
	payload := oauthStatePayload{
		ClientID:      clientID,
		Provider:      provider,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
	}
	if err := s.redis.SetJSON(ctx, oauthStateKey(state), payload, oauthStateTTL); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "保存 OAuth state 失败", err)
	}
	return &OAuthStartResult{
		AuthorizeURL: p.AuthURL(state, redirectURI, codeChallenge),
		State:        state,
	}, nil
}

// ConsumeState 一次性校验并消费 state，返回登录时必须对齐的 redirect_uri / provider。
func (s *OAuthService) ConsumeState(ctx context.Context, clientID, provider, state, redirectURI string) error {
	if state == "" {
		return errcode.New(errcode.BadRequest, "缺少 state")
	}
	var payload oauthStatePayload
	ok, err := s.redis.GetDelJSON(ctx, oauthStateKey(state), &payload)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "读取 OAuth state 失败", err)
	}
	if !ok {
		return errcode.New(errcode.InvalidCred, "state 无效或已过期")
	}
	if payload.ClientID != clientID {
		return errcode.New(errcode.InvalidCred, "state 与应用不匹配")
	}
	if payload.Provider != provider {
		return errcode.New(errcode.InvalidCred, "state 与 provider 不匹配")
	}
	if payload.RedirectURI != redirectURI {
		return errcode.New(errcode.InvalidCred, "redirect_uri 与授权时不一致")
	}
	return nil
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
