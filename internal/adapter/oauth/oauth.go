package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// Registry 管理多个 Provider。
type Registry struct {
	providers map[string]adapter.OAuthProvider
}

func NewRegistry(cfgs map[string]config.OAuthProviderConfig) *Registry {
	r := &Registry{providers: map[string]adapter.OAuthProvider{}}
	for name, cfg := range cfgs {
		if cfg.ClientID == "" {
			continue
		}
		r.providers[name] = NewGeneric(name, cfg)
	}
	return r
}

func (r *Registry) Get(name string) (adapter.OAuthProvider, bool) {
	p, ok := r.providers[name]
	return p, ok
}

func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.providers))
	for k := range r.providers {
		out = append(out, k)
	}
	return out
}
