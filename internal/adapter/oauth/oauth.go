package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/davveo/unified-account-center/internal/adapter"
	"github.com/davveo/unified-account-center/internal/config"
)

type GenericProvider struct {
	name   string
	cfg    config.OAuthProviderConfig
	client *http.Client
}

func NewGeneric(name string, cfg config.OAuthProviderConfig) *GenericProvider {
	return &GenericProvider{
		name: name,
		cfg:  cfg,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (p *GenericProvider) Name() string { return p.name }

func (p *GenericProvider) AuthURL(state, redirectURI, codeChallenge string) string {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("state", state)
	if len(p.cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	return p.cfg.AuthURL + "?" + q.Encode()
}

func (p *GenericProvider) Exchange(ctx context.Context, code, redirectURI, codeVerifier string) (*adapter.OAuthUserInfo, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("empty access_token")
	}

	ureq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	ureq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	ureq.Header.Set("Accept", "application/json")
	uresp, err := p.client.Do(ureq)
	if err != nil {
		return nil, err
	}
	defer uresp.Body.Close()
	ubody, _ := io.ReadAll(uresp.Body)
	if uresp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo failed: %s", string(ubody))
	}

	info, err := mapUserInfo(p.name, ubody)
	if err != nil {
		return nil, err
	}
	info.RawJSON = string(ubody)
	return info, nil
}

// WeChatProvider 微信开放平台网站应用扫码登录。
type WeChatProvider struct {
	name   string
	cfg    config.OAuthProviderConfig
	client *http.Client
}

func NewWeChat(name string, cfg config.OAuthProviderConfig) *WeChatProvider {
	if cfg.AuthURL == "" {
		cfg.AuthURL = "https://open.weixin.qq.com/connect/qrconnect"
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = "https://api.weixin.qq.com/sns/oauth2/access_token"
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = "https://api.weixin.qq.com/sns/userinfo"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"snsapi_login"}
	}
	return &WeChatProvider{name: name, cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}}
}

func (p *WeChatProvider) Name() string { return p.name }

func (p *WeChatProvider) AuthURL(state, redirectURI, codeChallenge string) string {
	q := url.Values{}
	q.Set("appid", p.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(p.cfg.Scopes, ","))
	q.Set("state", state)
	// 微信不支持标准 PKCE；codeChallenge 忽略，由中台侧托管授权码 PKCE 保护
	_ = codeChallenge
	return p.cfg.AuthURL + "?" + q.Encode() + "#wechat_redirect"
}

func (p *WeChatProvider) Exchange(ctx context.Context, code, redirectURI, codeVerifier string) (*adapter.OAuthUserInfo, error) {
	_ = redirectURI
	_ = codeVerifier
	q := url.Values{}
	q.Set("appid", p.cfg.ClientID)
	q.Set("secret", p.cfg.ClientSecret)
	q.Set("code", code)
	q.Set("grant_type", "authorization_code")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.TokenURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		OpenID      string `json:"openid"`
		UnionID     string `json:"unionid"`
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}
	if tokenResp.ErrCode != 0 || tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("wechat token: %s", string(body))
	}
	uq := url.Values{}
	uq.Set("access_token", tokenResp.AccessToken)
	uq.Set("openid", tokenResp.OpenID)
	ureq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserInfoURL+"?"+uq.Encode(), nil)
	if err != nil {
		return nil, err
	}
	uresp, err := p.client.Do(ureq)
	if err != nil {
		return nil, err
	}
	defer uresp.Body.Close()
	ubody, _ := io.ReadAll(uresp.Body)
	var u struct {
		OpenID  string `json:"openid"`
		UnionID string `json:"unionid"`
		Nick    string `json:"nickname"`
		Avatar  string `json:"headimgurl"`
		ErrCode int    `json:"errcode"`
	}
	if err := json.Unmarshal(ubody, &u); err != nil {
		return nil, err
	}
	if u.ErrCode != 0 {
		return nil, fmt.Errorf("wechat userinfo: %s", string(ubody))
	}
	sub := u.UnionID
	if sub == "" {
		sub = u.OpenID
	}
	if sub == "" {
		sub = tokenResp.UnionID
	}
	if sub == "" {
		sub = tokenResp.OpenID
	}
	return &adapter.OAuthUserInfo{
		Subject: sub,
		Name:    u.Nick,
		Avatar:  u.Avatar,
		RawJSON: string(ubody),
	}, nil
}

// WeComProvider 企业微信网页授权（简化：OAuth code 换 user_ticket/userinfo）。
type WeComProvider struct {
	name   string
	cfg    config.OAuthProviderConfig
	client *http.Client
}

func NewWeCom(name string, cfg config.OAuthProviderConfig) *WeComProvider {
	if cfg.AuthURL == "" {
		cfg.AuthURL = "https://open.weixin.qq.com/connect/oauth2/authorize"
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"snsapi_base"}
	}
	return &WeComProvider{name: name, cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}}
}

func (p *WeComProvider) Name() string { return p.name }

func (p *WeComProvider) AuthURL(state, redirectURI, codeChallenge string) string {
	_ = codeChallenge
	q := url.Values{}
	q.Set("appid", p.cfg.ClientID) // corpid
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(p.cfg.Scopes, ","))
	q.Set("state", state)
	return p.cfg.AuthURL + "?" + q.Encode() + "#wechat_redirect"
}

func (p *WeComProvider) Exchange(ctx context.Context, code, redirectURI, codeVerifier string) (*adapter.OAuthUserInfo, error) {
	_ = redirectURI
	_ = codeVerifier
	// 1) corp access_token
	tq := url.Values{}
	tq.Set("corpid", p.cfg.ClientID)
	tq.Set("corpsecret", p.cfg.ClientSecret)
	treq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.TokenURL+"?"+tq.Encode(), nil)
	if err != nil {
		return nil, err
	}
	tresp, err := p.client.Do(treq)
	if err != nil {
		return nil, err
	}
	defer tresp.Body.Close()
	tbody, _ := io.ReadAll(tresp.Body)
	var tok struct {
		AccessToken string `json:"access_token"`
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
	}
	if err := json.Unmarshal(tbody, &tok); err != nil {
		return nil, err
	}
	if tok.ErrCode != 0 || tok.AccessToken == "" {
		return nil, fmt.Errorf("wecom token: %s", string(tbody))
	}
	uq := url.Values{}
	uq.Set("access_token", tok.AccessToken)
	uq.Set("code", code)
	ureq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserInfoURL+"?"+uq.Encode(), nil)
	if err != nil {
		return nil, err
	}
	uresp, err := p.client.Do(ureq)
	if err != nil {
		return nil, err
	}
	defer uresp.Body.Close()
	ubody, _ := io.ReadAll(uresp.Body)
	var u struct {
		UserID  string `json:"UserId"`
		OpenID  string `json:"OpenId"`
		ErrCode int    `json:"errcode"`
	}
	if err := json.Unmarshal(ubody, &u); err != nil {
		return nil, err
	}
	if u.ErrCode != 0 {
		return nil, fmt.Errorf("wecom userinfo: %s", string(ubody))
	}
	sub := u.UserID
	if sub == "" {
		sub = u.OpenID
	}
	if sub == "" {
		return nil, fmt.Errorf("wecom subject empty")
	}
	return &adapter.OAuthUserInfo{Subject: sub, RawJSON: string(ubody)}, nil
}

func mapUserInfo(provider string, body []byte) (*adapter.OAuthUserInfo, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	info := &adapter.OAuthUserInfo{}
	switch provider {
	case "github":
		info.Subject = fmt.Sprintf("%v", m["id"])
		if v, ok := m["login"].(string); ok {
			info.Name = v
		}
		if v, ok := m["avatar_url"].(string); ok {
			info.Avatar = v
		}
		if v, ok := m["email"].(string); ok {
			info.Email = v
		}
	case "google", "apple":
		if v, ok := m["sub"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		}
		if v, ok := m["name"].(string); ok {
			info.Name = v
		}
		if v, ok := m["picture"].(string); ok {
			info.Avatar = v
		}
		if v, ok := m["email"].(string); ok {
			info.Email = v
		}
	case "feishu", "lark":
		data, _ := m["data"].(map[string]interface{})
		if data == nil {
			data = m
		}
		if v, ok := data["open_id"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		} else if v, ok := data["union_id"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		} else if v, ok := data["sub"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		}
		if v, ok := data["name"].(string); ok {
			info.Name = v
		}
		if v, ok := data["avatar_url"].(string); ok {
			info.Avatar = v
		}
		if v, ok := data["email"].(string); ok {
			info.Email = v
		}
	case "dingtalk":
		if v, ok := m["openId"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		} else if v, ok := m["unionId"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		} else if v, ok := m["sub"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		}
		if v, ok := m["nick"].(string); ok {
			info.Name = v
		} else if v, ok := m["name"].(string); ok {
			info.Name = v
		}
		if v, ok := m["avatarUrl"].(string); ok {
			info.Avatar = v
		}
		if v, ok := m["email"].(string); ok {
			info.Email = v
		}
	default:
		if v, ok := m["sub"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		} else if v, ok := m["id"]; ok {
			info.Subject = fmt.Sprintf("%v", v)
		}
		if v, ok := m["name"].(string); ok {
			info.Name = v
		}
		if v, ok := m["avatar"].(string); ok {
			info.Avatar = v
		} else if v, ok := m["picture"].(string); ok {
			info.Avatar = v
		}
		if v, ok := m["email"].(string); ok {
			info.Email = v
		}
	}
	if info.Subject == "" || info.Subject == "<nil>" {
		return nil, fmt.Errorf("oauth subject empty")
	}
	return info, nil
}

func buildProvider(name string, cfg config.OAuthProviderConfig) adapter.OAuthProvider {
	kind := strings.ToLower(cfg.Kind)
	if kind == "" {
		switch strings.ToLower(name) {
		case "wechat":
			kind = "wechat"
		case "wecom", "wechat_work", "enterprise_wechat":
			kind = "wecom"
		case "apple", "google", "dingtalk", "feishu", "lark":
			kind = strings.ToLower(name)
			if kind == "lark" {
				kind = "feishu"
			}
		default:
			kind = "generic"
		}
	}
	// 标准 OIDC / OAuth2 厂商：补齐默认端点后走 Generic
	cfg = applyOAuthPresets(name, kind, cfg)
	switch kind {
	case "wechat":
		return NewWeChat(name, cfg)
	case "wecom":
		return NewWeCom(name, cfg)
	default:
		return NewGeneric(name, cfg)
	}
}

func applyOAuthPresets(name, kind string, cfg config.OAuthProviderConfig) config.OAuthProviderConfig {
	k := kind
	if k == "" || k == "generic" {
		k = strings.ToLower(name)
	}
	switch k {
	case "google":
		if cfg.AuthURL == "" {
			cfg.AuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
		}
		if cfg.TokenURL == "" {
			cfg.TokenURL = "https://oauth2.googleapis.com/token"
		}
		if cfg.UserInfoURL == "" {
			cfg.UserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
		}
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = []string{"openid", "email", "profile"}
		}
	case "apple":
		if cfg.AuthURL == "" {
			cfg.AuthURL = "https://appleid.apple.com/auth/authorize"
		}
		if cfg.TokenURL == "" {
			cfg.TokenURL = "https://appleid.apple.com/auth/token"
		}
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = []string{"name", "email"}
		}
	case "dingtalk":
		if cfg.AuthURL == "" {
			cfg.AuthURL = "https://login.dingtalk.com/oauth2/auth"
		}
		if cfg.TokenURL == "" {
			cfg.TokenURL = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
		}
		if cfg.UserInfoURL == "" {
			cfg.UserInfoURL = "https://api.dingtalk.com/v1.0/contact/users/me"
		}
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = []string{"openid"}
		}
	case "feishu", "lark":
		if cfg.AuthURL == "" {
			cfg.AuthURL = "https://open.feishu.cn/open-apis/authen/v1/authorize"
		}
		if cfg.TokenURL == "" {
			cfg.TokenURL = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
		}
		if cfg.UserInfoURL == "" {
			cfg.UserInfoURL = "https://open.feishu.cn/open-apis/authen/v1/user_info"
		}
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = []string{"openid", "email"}
		}
	}
	return cfg
}

// Registry 管理多个 Provider，支持热更新。
type Registry struct {
	mu        sync.RWMutex
	providers map[string]adapter.OAuthProvider
	cfgs      map[string]config.OAuthProviderConfig
}

func NewRegistry(cfgs map[string]config.OAuthProviderConfig) *Registry {
	r := &Registry{
		providers: map[string]adapter.OAuthProvider{},
		cfgs:      map[string]config.OAuthProviderConfig{},
	}
	for name, cfg := range cfgs {
		r.Upsert(name, cfg)
	}
	return r
}

func (r *Registry) Upsert(name string, cfg config.OAuthProviderConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfgs[name] = cfg
	if cfg.ClientID == "" {
		delete(r.providers, name)
		return
	}
	r.providers[name] = buildProvider(name, cfg)
}

func (r *Registry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, name)
	delete(r.cfgs, name)
}

func (r *Registry) Get(name string) (adapter.OAuthProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

func (r *Registry) GetConfig(name string) (config.OAuthProviderConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.cfgs[name]
	return c, ok
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.providers))
	for k := range r.providers {
		out = append(out, k)
	}
	return out
}

func (r *Registry) ListConfigs() map[string]config.OAuthProviderConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]config.OAuthProviderConfig, len(r.cfgs))
	for k, v := range r.cfgs {
		cp := v
		cp.ClientSecret = "" // 不回传密钥
		out[k] = cp
	}
	return out
}
