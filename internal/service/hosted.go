package service

import (
	"context"
	"time"

	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/pkg/pkce"
)

const hostedCodeTTL = 5 * time.Minute

type HostedConfig struct {
	ClientID        string   `json:"client_id"`
	Name            string   `json:"name"`
	LoginTitle      string   `json:"login_title"`
	LogoURL         string   `json:"logo_url"`
	ThemeColor      string   `json:"theme_color"`
	AllowedMethods  []string `json:"allowed_methods"`
	OAuthProviders  []string `json:"oauth_providers"`
	RequirePKCE     bool     `json:"require_pkce"`
	RequireMFA      bool     `json:"require_mfa"`
	CaptchaEnabled  bool     `json:"captcha_enabled"`
	CaptchaProvider string   `json:"captcha_provider"`
	CaptchaSiteKey  string   `json:"captcha_site_key,omitempty"`
	SSOEnabled      bool     `json:"sso_enabled"`
}

func (s *AuthService) HostedConfig(ctx context.Context, clientID string) (*HostedConfig, error) {
	app, err := s.requireApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	title := app.LoginTitle
	if title == "" {
		title = app.Name
	}
	theme := app.ThemeColor
	if theme == "" {
		theme = "#1f6feb"
	}
	return &HostedConfig{
		ClientID:        app.ClientID,
		Name:            app.Name,
		LoginTitle:      title,
		LogoURL:         app.LogoURL,
		ThemeColor:      theme,
		AllowedMethods:  append([]string{}, app.AllowedMethods...),
		OAuthProviders:  append([]string{}, app.OAuthProviders...),
		RequirePKCE:     app.RequirePKCE,
		RequireMFA:      app.RequireMFA,
		CaptchaEnabled:  s.cfg.Captcha.Enabled,
		CaptchaProvider: s.cfg.Captcha.Provider,
		CaptchaSiteKey:  s.cfg.Captcha.SiteKey,
		SSOEnabled:      true,
	}, nil
}

type IssueHostedCodeDTO struct {
	RedirectURI   string `json:"redirect_uri" binding:"required"`
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
}

type IssueHostedCodeResult struct {
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
}

type hostedCodePayload struct {
	ClientID      string   `json:"client_id"`
	UserID        string   `json:"user_id"`
	RedirectURI   string   `json:"redirect_uri"`
	State         string   `json:"state"`
	CodeChallenge string   `json:"code_challenge,omitempty"`
	Token         TokenDTO `json:"token"`
	DeviceID      string   `json:"device_id"`
}

func (s *AuthService) IssueHostedCode(ctx context.Context, meta RequestMeta, userID string, token TokenDTO, deviceID string, dto IssueHostedCodeDTO) (*IssueHostedCodeResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	if !redirectAllowed(app.RedirectURIs, dto.RedirectURI) {
		return nil, errcode.New(errcode.BadRequest, "redirect_uri 不在白名单")
	}
	if app.RequirePKCE && dto.CodeChallenge == "" {
		return nil, errcode.New(errcode.BadRequest, "应用要求 PKCE，缺少 code_challenge")
	}
	code := idgen.New("ac") + idgen.RandomHex(12)
	payload := hostedCodePayload{
		ClientID:      app.ClientID,
		UserID:        userID,
		RedirectURI:   dto.RedirectURI,
		State:         dto.State,
		CodeChallenge: dto.CodeChallenge,
		Token:         token,
		DeviceID:      deviceID,
	}
	if err := s.redis.SetJSON(ctx, "uac:hosted:code:"+code, payload, hostedCodeTTL); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "保存授权码失败", err)
	}
	s.audit(ctx, app, userID, "hosted_code_issued", true, dto.RedirectURI, meta)
	return &IssueHostedCodeResult{Code: code, RedirectURI: dto.RedirectURI, State: dto.State}, nil
}

type ExchangeTokenDTO struct {
	GrantType    string `json:"grant_type" binding:"required"` // authorization_code
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
}

type ExchangeTokenResult struct {
	Token    TokenDTO `json:"token"`
	UserID   string   `json:"user_id"`
	DeviceID string   `json:"device_id,omitempty"`
}

func (s *AuthService) ExchangeToken(ctx context.Context, meta RequestMeta, dto ExchangeTokenDTO) (*ExchangeTokenResult, error) {
	if dto.GrantType != "authorization_code" {
		return nil, errcode.New(errcode.BadRequest, "仅支持 grant_type=authorization_code")
	}
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	if dto.Code == "" || dto.RedirectURI == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 code 或 redirect_uri")
	}
	var payload hostedCodePayload
	ok, err := s.redis.GetJSON(ctx, "uac:hosted:code:"+dto.Code, &payload)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "读取授权码失败", err)
	}
	if !ok {
		return nil, errcode.New(errcode.InvalidCred, "授权码无效或已过期")
	}
	if payload.ClientID != app.ClientID {
		return nil, errcode.New(errcode.InvalidCred, "授权码与应用不匹配")
	}
	if payload.RedirectURI != dto.RedirectURI {
		return nil, errcode.New(errcode.InvalidCred, "redirect_uri 不匹配")
	}
	if payload.CodeChallenge != "" {
		if !pkce.VerifyS256(dto.CodeVerifier, payload.CodeChallenge) {
			return nil, errcode.New(errcode.InvalidCred, "PKCE 校验失败")
		}
	} else if app.RequirePKCE {
		return nil, errcode.New(errcode.InvalidCred, "缺少 PKCE")
	}
	// 校验通过后再消费，避免错误 verifier 误删授权码
	_ = s.redis.Del(ctx, "uac:hosted:code:"+dto.Code)
	s.audit(ctx, app, payload.UserID, "hosted_code_exchanged", true, "", meta)
	tok := payload.Token
	tok.DeviceID = payload.DeviceID
	return &ExchangeTokenResult{Token: tok, UserID: payload.UserID, DeviceID: payload.DeviceID}, nil
}

type SessionView struct {
	JTI       string `json:"jti"`
	ClientID  string `json:"client_id"`
	DeviceID  string `json:"device_id"`
	IP        string `json:"ip"`
	UA        string `json:"ua"`
	ExpireAt  string `json:"expire_at"`
	CreatedAt string `json:"created_at"`
	Current   bool   `json:"current,omitempty"`
}

func (s *AuthService) ListSessions(ctx context.Context, meta RequestMeta, userID, currentRefreshJTI string) ([]SessionView, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	list, err := s.repos.Refresh.ListActiveByUser(ctx, userID, app.ClientID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询会话失败", err)
	}
	out := make([]SessionView, 0, len(list))
	for _, rt := range list {
		out = append(out, SessionView{
			JTI: rt.JTI, ClientID: rt.ClientID, DeviceID: rt.DeviceID,
			IP: rt.IP, UA: rt.UA,
			ExpireAt:  rt.ExpireAt.Format(time.RFC3339),
			CreatedAt: rt.CreatedAt.Format(time.RFC3339),
			Current:   currentRefreshJTI != "" && rt.JTI == currentRefreshJTI,
		})
	}
	return out, nil
}

func (s *AuthService) RevokeSession(ctx context.Context, meta RequestMeta, userID, jti string) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	rt, err := s.repos.Refresh.FindByJTI(ctx, jti)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "查询会话失败", err)
	}
	if rt == nil || rt.UserID != userID || rt.ClientID != app.ClientID {
		return errcode.New(errcode.NotFound, "会话不存在")
	}
	if err := s.repos.Refresh.Revoke(ctx, jti, time.Now()); err != nil {
		return errcode.Wrap(errcode.Internal, "吊销会话失败", err)
	}
	s.audit(ctx, app, userID, "session_revoke", true, jti, meta)
	return nil
}

func (s *AuthService) RevokeOtherSessions(ctx context.Context, meta RequestMeta, userID, keepJTI string) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	if keepJTI == "" {
		return errcode.New(errcode.BadRequest, "需要 keep_jti（当前 refresh jti）或 refresh_token")
	}
	if err := s.repos.Refresh.RevokeOthers(ctx, userID, app.ClientID, keepJTI, time.Now()); err != nil {
		return errcode.Wrap(errcode.Internal, "退出其他设备失败", err)
	}
	s.audit(ctx, app, userID, "session_revoke_others", true, keepJTI, meta)
	return nil
}

// ResolveRefreshJTI 从 refresh_token 明文解析 jti（用于标记当前会话）。
func (s *AuthService) ResolveRefreshJTI(ctx context.Context, refreshToken string) string {
	if refreshToken == "" {
		return ""
	}
	rt, _ := s.repos.Refresh.FindByHash(ctx, crypto.HashToken(refreshToken))
	if rt == nil {
		return ""
	}
	return rt.JTI
}
