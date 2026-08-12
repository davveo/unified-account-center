package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/davveo/unified-account-center/internal/authenticator"
	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/identity"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/repository"
)

type AuthService struct {
	cfg   *config.Config
	repos *repository.Repos
	auths *authenticator.Registry
	jwt   *jwtutil.Manager
	redis *redisx.Client
}

func NewAuthService(cfg *config.Config, repos *repository.Repos, auths *authenticator.Registry, jwtMgr *jwtutil.Manager, redis *redisx.Client) *AuthService {
	return &AuthService{cfg: cfg, repos: repos, auths: auths, jwt: jwtMgr, redis: redis}
}

type ClientInfo struct {
	DeviceID string `json:"device_id"`
	Platform string `json:"platform"`
}

type LoginOptions struct {
	AutoRegister *bool `json:"auto_register"`
}

type ChallengeDTO struct {
	Method       string `json:"method" binding:"required"`
	Identity     string `json:"identity" binding:"required"`
	Scene        string `json:"scene"`
	CaptchaToken string `json:"captcha_token"`
}

type LoginDTO struct {
	Method     string            `json:"method" binding:"required"`
	Identity   string            `json:"identity"`
	Provider   string            `json:"provider"`
	Credential map[string]string `json:"credential"`
	Client     ClientInfo        `json:"client"`
	Options    LoginOptions      `json:"options"`
}

type TokenDTO struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpireIn        int64  `json:"expire_in"`
	RefreshToken    string `json:"refresh_token"`
	RefreshExpireIn int64  `json:"refresh_expire_in"`
}

type IdentityView struct {
	Type     string `json:"type"`
	Provider string `json:"provider,omitempty"`
	Value    string `json:"value"`
	Verified bool   `json:"verified"`
}

type UserView struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
	Avatar      string `json:"avatar"`
	Status      string `json:"status"`
}

type LoginResult struct {
	User       UserView       `json:"user"`
	Identities []IdentityView `json:"identities"`
	Token      TokenDTO       `json:"token"`
	IsNewUser  bool           `json:"is_new_user"`
}

type RequestMeta struct {
	ClientID string
	IP       string
	UA       string
}

func (s *AuthService) ListMethods(ctx context.Context, clientID string) ([]string, error) {
	app, err := s.requireApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return append([]string{}, app.AllowedMethods...), nil
}

func (s *AuthService) Challenge(ctx context.Context, meta RequestMeta, dto ChallengeDTO) (*authenticator.ChallengeResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	if !methodAllowed(app, dto.Method) {
		return nil, errcode.New(errcode.ForbiddenApp, "应用未启用该登录方式")
	}
	auth, ok := s.auths.Get(dto.Method)
	if !ok {
		return nil, errcode.New(errcode.BadRequest, "不支持的登录方式")
	}
	scene := dto.Scene
	if scene == "" {
		scene = model.SceneLogin
	}
	res, err := auth.Challenge(ctx, authenticator.ChallengeRequest{
		ClientID:     meta.ClientID,
		TenantID:     app.TenantID,
		Method:       dto.Method,
		Identity:     dto.Identity,
		Scene:        scene,
		CaptchaToken: dto.CaptchaToken,
		IP:           meta.IP,
	})
	s.audit(ctx, app, "", "challenge", err == nil, dto.Method+":"+dto.Identity, meta)
	return res, err
}

func (s *AuthService) Login(ctx context.Context, meta RequestMeta, dto LoginDTO) (*LoginResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	if !methodAllowed(app, dto.Method) {
		return nil, errcode.New(errcode.ForbiddenApp, "应用未启用该登录方式")
	}
	auth, ok := s.auths.Get(dto.Method)
	if !ok {
		return nil, errcode.New(errcode.BadRequest, "不支持的登录方式")
	}
	if dto.Credential == nil {
		dto.Credential = map[string]string{}
	}

	principal, err := auth.Verify(ctx, authenticator.VerifyRequest{
		ClientID:   meta.ClientID,
		TenantID:   app.TenantID,
		Method:     dto.Method,
		Identity:   dto.Identity,
		Provider:   dto.Provider,
		Credential: dto.Credential,
		Scene:      model.SceneLogin,
	})
	if err != nil {
		s.audit(ctx, app, "", "login_fail", false, dto.Method, meta)
		return nil, err
	}

	autoReg := app.AutoRegister
	if dto.Options.AutoRegister != nil {
		autoReg = *dto.Options.AutoRegister
	}

	user, isNew, err := s.resolveUser(ctx, app, principal, autoReg)
	if err != nil {
		s.audit(ctx, app, "", "login_fail", false, err.Error(), meta)
		return nil, err
	}

	token, err := s.issueTokens(ctx, app, user, dto.Client, meta)
	if err != nil {
		return nil, err
	}
	views, _ := s.identityViews(ctx, user.UserID)
	s.audit(ctx, app, user.UserID, "login_ok", true, dto.Method, meta)
	return &LoginResult{
		User: UserView{
			UserID:      user.UserID,
			DisplayName: user.DisplayName,
			Avatar:      user.Avatar,
			Status:      user.Status,
		},
		Identities: views,
		Token:      *token,
		IsNewUser:  isNew,
	}, nil
}

func (s *AuthService) Refresh(ctx context.Context, meta RequestMeta, refreshToken string) (*TokenDTO, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	if refreshToken == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 refresh_token")
	}
	hash := crypto.HashToken(refreshToken)
	rt, err := s.repos.Refresh.FindByHash(ctx, hash)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询 refresh 失败", err)
	}
	if rt == nil || rt.ClientID != app.ClientID {
		return nil, errcode.New(errcode.InvalidCred, "refresh_token 无效")
	}
	if rt.RevokedAt != nil {
		// 复用检测：撤销该用户全部 refresh
		_ = s.repos.Refresh.RevokeAllByUser(ctx, rt.UserID, rt.ClientID, time.Now())
		return nil, errcode.New(errcode.InvalidCred, "refresh_token 已失效")
	}
	if time.Now().After(rt.ExpireAt) {
		return nil, errcode.New(errcode.InvalidCred, "refresh_token 已过期")
	}
	user, err := s.repos.User.FindByUserID(ctx, rt.UserID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.InvalidCred, "用户不存在")
	}

	newToken, err := s.issueTokens(ctx, app, user, ClientInfo{DeviceID: rt.DeviceID}, meta)
	if err != nil {
		return nil, err
	}
	// rotation：旧 token 标记替换
	_ = s.repos.Refresh.MarkReplaced(ctx, rt.JTI, "", time.Now())
	s.audit(ctx, app, user.UserID, "token_refresh", true, "", meta)
	return newToken, nil
}

func (s *AuthService) Logout(ctx context.Context, meta RequestMeta, userID, accessJTI string, refreshToken string, allDevices bool, accessTTL time.Duration) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	now := time.Now()
	if allDevices {
		_ = s.repos.Refresh.RevokeAllByUser(ctx, userID, app.ClientID, now)
	} else if refreshToken != "" {
		if rt, _ := s.repos.Refresh.FindByHash(ctx, crypto.HashToken(refreshToken)); rt != nil {
			_ = s.repos.Refresh.Revoke(ctx, rt.JTI, now)
		}
	}
	if accessJTI != "" {
		_ = s.redis.BlacklistAccess(ctx, accessJTI, accessTTL)
	}
	s.audit(ctx, app, userID, "logout", true, "", meta)
	return nil
}

func (s *AuthService) Me(ctx context.Context, userID string) (*LoginResult, error) {
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	views, _ := s.identityViews(ctx, userID)
	return &LoginResult{
		User: UserView{
			UserID:      user.UserID,
			DisplayName: user.DisplayName,
			Avatar:      user.Avatar,
			Status:      user.Status,
		},
		Identities: views,
	}, nil
}

func (s *AuthService) Introspect(ctx context.Context, token string) (map[string]interface{}, error) {
	claims, err := s.jwt.ParseAccess(token)
	if err != nil {
		return map[string]interface{}{"active": false}, nil
	}
	bl, err := s.redis.IsAccessBlacklisted(ctx, claims.ID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询黑名单失败", err)
	}
	if bl {
		return map[string]interface{}{"active": false}, nil
	}
	exp := int64(0)
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	return map[string]interface{}{
		"active":    true,
		"user_id":   claims.UserID,
		"client_id": claims.ClientID,
		"tenant_id": claims.TenantID,
		"exp":       exp,
		"jti":       claims.ID,
	}, nil
}

func (s *AuthService) Bind(ctx context.Context, meta RequestMeta, userID string, dto LoginDTO) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	if !methodAllowed(app, dto.Method) {
		return errcode.New(errcode.ForbiddenApp, "应用未启用该登录方式")
	}
	auth, ok := s.auths.Get(dto.Method)
	if !ok {
		return errcode.New(errcode.BadRequest, "不支持的登录方式")
	}
	if dto.Credential == nil {
		dto.Credential = map[string]string{}
	}
	principal, err := auth.Verify(ctx, authenticator.VerifyRequest{
		ClientID:   meta.ClientID,
		TenantID:   app.TenantID,
		Method:     dto.Method,
		Identity:   dto.Identity,
		Provider:   dto.Provider,
		Credential: dto.Credential,
		Scene:      model.SceneBind,
	})
	if err != nil {
		s.audit(ctx, app, userID, "bind_fail", false, dto.Method, meta)
		return err
	}

	existing, err := s.repos.Identity.FindByUnique(ctx, app.TenantID, principal.Type, principal.Provider, principal.Identifier)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "查询身份失败", err)
	}
	if existing != nil {
		if existing.UserID == userID {
			return nil
		}
		return errcode.New(errcode.ConflictAccount, "该账户已被其他用户绑定")
	}
	if err := s.repos.Identity.Create(ctx, &model.Identity{
		TenantID:   app.TenantID,
		UserID:     userID,
		Type:       principal.Type,
		Provider:   principal.Provider,
		Identifier: principal.Identifier,
		Verified:   principal.Verified,
	}); err != nil {
		return errcode.Wrap(errcode.Internal, "绑定失败", err)
	}
	if principal.Type == model.IdentityOAuth {
		raw, _ := json.Marshal(principal.Profile)
		_ = s.repos.OAuth.Upsert(ctx, &model.OAuthAccount{
			UserID:      userID,
			Provider:    principal.Provider,
			Subject:     principal.Identifier,
			ProfileJSON: string(raw),
		})
	}
	s.audit(ctx, app, userID, "bind_ok", true, principal.Type+":"+principal.Identifier, meta)
	return nil
}

type UnbindDTO struct {
	Type     string `json:"type" binding:"required"`
	Provider string `json:"provider"`
	Value    string `json:"value"`
}

func (s *AuthService) Unbind(ctx context.Context, meta RequestMeta, userID string, dto UnbindDTO) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	list, err := s.repos.Identity.ListByUserID(ctx, userID)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "查询身份失败", err)
	}
	if len(list) <= 1 {
		return errcode.New(errcode.BadRequest, "至少保留一种登录方式")
	}

	var target *model.Identity
	for i := range list {
		id := &list[i]
		if id.Type != dto.Type {
			continue
		}
		if dto.Type == model.IdentityOAuth && id.Provider != dto.Provider {
			continue
		}
		if dto.Value != "" {
			norm := dto.Value
			switch dto.Type {
			case model.IdentityPhone:
				if n, e := identity.NormalizePhone(dto.Value); e == nil {
					norm = n
				}
			case model.IdentityEmail:
				if n, e := identity.NormalizeEmail(dto.Value); e == nil {
					norm = n
				}
			}
			if id.Identifier != norm {
				continue
			}
		}
		target = id
		break
	}
	if target == nil {
		return errcode.New(errcode.NotFound, "未找到要解绑的账户")
	}
	if err := s.repos.Identity.Delete(ctx, target.ID); err != nil {
		return errcode.Wrap(errcode.Internal, "解绑失败", err)
	}
	s.audit(ctx, app, userID, "unbind_ok", true, target.Type+":"+target.Identifier, meta)
	return nil
}

type SetPasswordDTO struct {
	Password string `json:"password" binding:"required"`
}

func (s *AuthService) SetPassword(ctx context.Context, meta RequestMeta, userID string, dto SetPasswordDTO) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	if err := s.validatePassword(dto.Password); err != nil {
		return err
	}
	hash, err := crypto.HashPassword(dto.Password)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "密码哈希失败", err)
	}
	if err := s.repos.Credential.UpsertPassword(ctx, userID, hash); err != nil {
		return errcode.Wrap(errcode.Internal, "保存密码失败", err)
	}
	s.audit(ctx, app, userID, "password_set", true, "", meta)
	return nil
}

type ResetStartDTO struct {
	Method   string `json:"method" binding:"required"`
	Identity string `json:"identity" binding:"required"`
}

func (s *AuthService) ResetPasswordStart(ctx context.Context, meta RequestMeta, dto ResetStartDTO) (*authenticator.ChallengeResult, error) {
	method := dto.Method
	if method == model.MethodPhonePassword {
		method = model.MethodPhoneOTP
	}
	if method == model.MethodEmailPassword {
		method = model.MethodEmailOTP
	}
	return s.Challenge(ctx, meta, ChallengeDTO{
		Method:   method,
		Identity: dto.Identity,
		Scene:    model.SceneResetPassword,
	})
}

type ResetConfirmDTO struct {
	Method      string `json:"method" binding:"required"`
	Identity    string `json:"identity" binding:"required"`
	ChallengeID string `json:"challenge_id" binding:"required"`
	OTP         string `json:"otp" binding:"required"`
	Password    string `json:"password" binding:"required"`
}

func (s *AuthService) ResetPasswordConfirm(ctx context.Context, meta RequestMeta, dto ResetConfirmDTO) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	method := dto.Method
	if method == model.MethodPhonePassword {
		method = model.MethodPhoneOTP
	}
	if method == model.MethodEmailPassword {
		method = model.MethodEmailOTP
	}
	auth, ok := s.auths.Get(method)
	if !ok {
		return errcode.New(errcode.BadRequest, "不支持的方式")
	}
	principal, err := auth.Verify(ctx, authenticator.VerifyRequest{
		ClientID: meta.ClientID,
		TenantID: app.TenantID,
		Method:   method,
		Identity: dto.Identity,
		Credential: map[string]string{
			"challenge_id": dto.ChallengeID,
			"otp":          dto.OTP,
		},
		Scene: model.SceneResetPassword,
	})
	if err != nil {
		return err
	}
	idn, err := s.repos.Identity.FindByUnique(ctx, app.TenantID, principal.Type, principal.Provider, principal.Identifier)
	if err != nil || idn == nil {
		return errcode.New(errcode.NotFound, "用户不存在")
	}
	if err := s.validatePassword(dto.Password); err != nil {
		return err
	}
	hash, err := crypto.HashPassword(dto.Password)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "密码哈希失败", err)
	}
	if err := s.repos.Credential.UpsertPassword(ctx, idn.UserID, hash); err != nil {
		return errcode.Wrap(errcode.Internal, "保存密码失败", err)
	}
	s.audit(ctx, app, idn.UserID, "password_reset", true, "", meta)
	return nil
}

func (s *AuthService) requireApp(ctx context.Context, clientID string) (*model.App, error) {
	if clientID == "" {
		return nil, errcode.New(errcode.ForbiddenApp, "缺少 X-Client-Id")
	}
	app, err := s.repos.App.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询应用失败", err)
	}
	if app == nil {
		return nil, errcode.New(errcode.ForbiddenApp, "应用不存在")
	}
	if app.Status != "active" {
		return nil, errcode.New(errcode.ForbiddenApp, "应用已停用")
	}
	return app, nil
}

func methodAllowed(app *model.App, method string) bool {
	for _, m := range app.AllowedMethods {
		if m == method {
			return true
		}
	}
	return false
}

func (s *AuthService) resolveUser(ctx context.Context, app *model.App, principal *authenticator.IdentityPrincipal, autoReg bool) (*model.User, bool, error) {
	// 密码登录 Verify 已带 user_id
	if uid, ok := principal.Profile["user_id"].(string); ok && uid != "" {
		user, err := s.repos.User.FindByUserID(ctx, uid)
		if err != nil || user == nil {
			return nil, false, errcode.New(errcode.InvalidCred, "用户不存在")
		}
		if user.Status != model.UserStatusActive {
			return nil, false, errcode.New(errcode.ForbiddenApp, "用户已禁用")
		}
		return user, false, nil
	}

	existing, err := s.repos.Identity.FindByUnique(ctx, app.TenantID, principal.Type, principal.Provider, principal.Identifier)
	if err != nil {
		return nil, false, errcode.Wrap(errcode.Internal, "查询身份失败", err)
	}
	if existing != nil {
		user, err := s.repos.User.FindByUserID(ctx, existing.UserID)
		if err != nil || user == nil {
			return nil, false, errcode.New(errcode.Internal, "用户数据异常")
		}
		if user.Status != model.UserStatusActive {
			return nil, false, errcode.New(errcode.ForbiddenApp, "用户已禁用")
		}
		return user, false, nil
	}
	if !autoReg {
		return nil, false, errcode.New(errcode.NotFound, "用户不存在")
	}

	userID := idgen.New("u")
	display := ""
	avatar := ""
	if principal.Profile != nil {
		if v, ok := principal.Profile["name"].(string); ok {
			display = v
		}
		if v, ok := principal.Profile["avatar"].(string); ok {
			avatar = v
		}
	}
	if display == "" {
		display = defaultDisplay(principal)
	}
	user := &model.User{
		UserID:      userID,
		TenantID:    app.TenantID,
		DisplayName: display,
		Avatar:      avatar,
		Status:      model.UserStatusActive,
	}
	if err := s.repos.User.Create(ctx, user); err != nil {
		return nil, false, errcode.Wrap(errcode.Internal, "创建用户失败", err)
	}
	if err := s.repos.Identity.Create(ctx, &model.Identity{
		TenantID:   app.TenantID,
		UserID:     userID,
		Type:       principal.Type,
		Provider:   principal.Provider,
		Identifier: principal.Identifier,
		Verified:   principal.Verified,
	}); err != nil {
		return nil, false, errcode.Wrap(errcode.Internal, "创建身份失败", err)
	}
	if principal.Type == model.IdentityOAuth {
		raw, _ := json.Marshal(principal.Profile)
		_ = s.repos.OAuth.Upsert(ctx, &model.OAuthAccount{
			UserID:      userID,
			Provider:    principal.Provider,
			Subject:     principal.Identifier,
			ProfileJSON: string(raw),
		})
	}
	return user, true, nil
}

func defaultDisplay(p *authenticator.IdentityPrincipal) string {
	switch p.Type {
	case model.IdentityPhone:
		return identity.MaskPhone(p.Identifier)
	case model.IdentityEmail:
		return identity.MaskEmail(p.Identifier)
	default:
		if p.Provider != "" {
			return p.Provider + ":" + p.Identifier
		}
		return p.Identifier
	}
}

func (s *AuthService) issueTokens(ctx context.Context, app *model.App, user *model.User, client ClientInfo, meta RequestMeta) (*TokenDTO, error) {
	accessTTL := time.Duration(app.AccessTTL) * time.Second
	if accessTTL <= 0 {
		accessTTL = s.cfg.JWT.AccessDuration()
	}
	refreshTTL := time.Duration(app.RefreshTTL) * time.Second
	if refreshTTL <= 0 {
		refreshTTL = s.cfg.JWT.RefreshDuration()
	}

	access, _, _, err := s.jwt.IssueAccess(user.UserID, app.ClientID, app.TenantID, accessTTL)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "签发 access_token 失败", err)
	}
	rtPlain := idgen.New("rt") + idgen.RandomHex(16)
	jti := idgen.New("rj")
	rt := &model.RefreshToken{
		JTI:       jti,
		TokenHash: crypto.HashToken(rtPlain),
		UserID:    user.UserID,
		ClientID:  app.ClientID,
		DeviceID:  client.DeviceID,
		IP:        meta.IP,
		UA:        meta.UA,
		ExpireAt:  time.Now().Add(refreshTTL),
	}
	if err := s.repos.Refresh.Create(ctx, rt); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "保存 refresh_token 失败", err)
	}
	return &TokenDTO{
		AccessToken:     access,
		TokenType:       "Bearer",
		ExpireIn:        int64(accessTTL.Seconds()),
		RefreshToken:    rtPlain,
		RefreshExpireIn: int64(refreshTTL.Seconds()),
	}, nil
}

func (s *AuthService) identityViews(ctx context.Context, userID string) ([]IdentityView, error) {
	list, err := s.repos.Identity.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]IdentityView, 0, len(list))
	for _, id := range list {
		v := IdentityView{Type: id.Type, Provider: id.Provider, Verified: id.Verified}
		switch id.Type {
		case model.IdentityPhone:
			v.Value = identity.MaskPhone(id.Identifier)
		case model.IdentityEmail:
			v.Value = identity.MaskEmail(id.Identifier)
		default:
			v.Value = id.Identifier
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *AuthService) validatePassword(pwd string) error {
	if len(pwd) < s.cfg.Password.MinLength {
		return errcode.New(errcode.BadRequest, "密码长度不足")
	}
	if s.cfg.Password.RequireLetterNumber {
		hasLetter, hasDigit := false, false
		for _, r := range pwd {
			if unicode.IsLetter(r) {
				hasLetter = true
			}
			if unicode.IsDigit(r) {
				hasDigit = true
			}
		}
		if !hasLetter || !hasDigit {
			return errcode.New(errcode.BadRequest, "密码需同时包含字母和数字")
		}
	}
	return nil
}

func (s *AuthService) audit(ctx context.Context, app *model.App, userID, action string, success bool, detail string, meta RequestMeta) {
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		TenantID: app.TenantID,
		ClientID: app.ClientID,
		UserID:   userID,
		Action:   action,
		Success:  success,
		Detail:   strings.TrimSpace(detail),
		IP:       meta.IP,
		UA:       meta.UA,
	})
}

func (s *AuthService) VerifyClientSecret(ctx context.Context, clientID, secret string) (*model.App, error) {
	app, err := s.requireApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if secret == "" || !crypto.VerifySecret(app.ClientSecretHash, secret) {
		return nil, errcode.New(errcode.ForbiddenApp, "应用凭证无效")
	}
	return app, nil
}
