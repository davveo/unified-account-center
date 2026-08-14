package service

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/repository"
)

type UpdateAppRequest struct {
	Name           *string  `json:"name"`
	Status         *string  `json:"status"` // active | disabled
	AllowedMethods []string `json:"allowed_methods"`
	RedirectURIs   []string `json:"redirect_uris"`
	CORSOrigins    []string `json:"cors_origins"`
	OAuthProviders []string `json:"oauth_providers"`
	AutoRegister   *bool    `json:"auto_register"`
	RequirePKCE    *bool    `json:"require_pkce"`
	LoginTitle     *string  `json:"login_title"`
	LogoURL        *string  `json:"logo_url"`
	ThemeColor     *string  `json:"theme_color"`
	AccessTTL      *int64   `json:"access_ttl"`
	RefreshTTL     *int64   `json:"refresh_ttl"`
}

func (s *AdminService) UpdateApp(ctx context.Context, clientID string, req UpdateAppRequest) (*AppView, error) {
	app, err := s.repos.App.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询应用失败", err)
	}
	if app == nil {
		return nil, errcode.New(errcode.NotFound, "应用不存在")
	}
	if req.Name != nil {
		app.Name = *req.Name
	}
	if req.Status != nil {
		switch *req.Status {
		case "active", "disabled":
			app.Status = *req.Status
		default:
			return nil, errcode.New(errcode.BadRequest, "status 仅支持 active/disabled")
		}
	}
	if req.AllowedMethods != nil {
		for _, m := range req.AllowedMethods {
			if !isKnownMethod(m) {
				return nil, errcode.New(errcode.BadRequest, "不支持的登录方式: "+m)
			}
		}
		app.AllowedMethods = req.AllowedMethods
	}
	if req.RedirectURIs != nil {
		app.RedirectURIs = req.RedirectURIs
	}
	if req.CORSOrigins != nil {
		app.CORSOrigins = req.CORSOrigins
	}
	if req.OAuthProviders != nil {
		app.OAuthProviders = req.OAuthProviders
	}
	if req.AutoRegister != nil {
		app.AutoRegister = *req.AutoRegister
	}
	if req.RequirePKCE != nil {
		app.RequirePKCE = *req.RequirePKCE
	}
	if req.LoginTitle != nil {
		app.LoginTitle = *req.LoginTitle
	}
	if req.LogoURL != nil {
		app.LogoURL = *req.LogoURL
	}
	if req.ThemeColor != nil {
		app.ThemeColor = *req.ThemeColor
	}
	if req.AccessTTL != nil && *req.AccessTTL > 0 {
		app.AccessTTL = *req.AccessTTL
	}
	if req.RefreshTTL != nil && *req.RefreshTTL > 0 {
		app.RefreshTTL = *req.RefreshTTL
	}
	if err := s.repos.App.Update(ctx, app); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "更新应用失败", err)
	}
	v := toAppView(app)
	return &v, nil
}

type RotateSecretResult struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (s *AdminService) RotateSecret(ctx context.Context, clientID, actor string) (*RotateSecretResult, error) {
	app, err := s.repos.App.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询应用失败", err)
	}
	if app == nil {
		return nil, errcode.New(errcode.NotFound, "应用不存在")
	}
	secret := idgen.RandomHex(24)
	hash, err := crypto.HashSecret(secret)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "生成密钥失败", err)
	}
	enc, err := crypto.SealSecret(s.secretSealKey(), secret)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "加密密钥失败", err)
	}
	app.ClientSecretHash = hash
	app.ClientSecretEnc = enc
	if err := s.repos.App.Update(ctx, app); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "轮换密钥失败", err)
	}
	_ = s.repos.DB.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("client_id = ? AND revoked_at IS NULL", clientID).
		Update("revoked_at", time.Now())
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		TenantID: app.TenantID, UserID: actor, ClientID: clientID,
		Action: "admin_rotate_secret", Success: true,
		Detail: "admin rotated client_secret", CreatedAt: time.Now(),
	})
	return &RotateSecretResult{ClientID: clientID, ClientSecret: secret}, nil
}

type UserAdminView struct {
	UserID      string `json:"user_id"`
	TenantID    string `json:"tenant_id"`
	DisplayName string `json:"display_name"`
	Avatar      string `json:"avatar"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func (s *AdminService) ListUsers(ctx context.Context, tenantID, keyword string, limit, offset int) ([]UserAdminView, int64, error) {
	list, total, err := s.repos.User.List(ctx, tenantID, keyword, limit, offset)
	if err != nil {
		return nil, 0, errcode.Wrap(errcode.Internal, "查询用户失败", err)
	}
	out := make([]UserAdminView, 0, len(list))
	for _, u := range list {
		out = append(out, UserAdminView{
			UserID:      u.UserID,
			TenantID:    u.TenantID,
			DisplayName: u.DisplayName,
			Avatar:      u.Avatar,
			Status:      u.Status,
			CreatedAt:   u.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt:   u.UpdatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return out, total, nil
}

func (s *AdminService) SetUserStatus(ctx context.Context, userID, status string) (*UserAdminView, error) {
	if status != model.UserStatusActive && status != model.UserStatusDisabled {
		return nil, errcode.New(errcode.BadRequest, "status 仅支持 active/disabled")
	}
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询用户失败", err)
	}
	if user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	user.Status = status
	if err := s.repos.User.Update(ctx, user); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "更新用户失败", err)
	}
	if status == model.UserStatusDisabled {
		_ = s.repos.Refresh.RevokeAllByUser(ctx, userID, "", time.Now())
		if s.webhookBus != nil {
			s.webhookBus.Emit(ctx, model.EventUserDisabled, user.TenantID, "", userID, map[string]interface{}{"status": status})
		}
	} else if s.webhookBus != nil {
		s.webhookBus.Emit(ctx, model.EventUserEnabled, user.TenantID, "", userID, map[string]interface{}{"status": status})
	}
	return &UserAdminView{
		UserID: user.UserID, TenantID: user.TenantID, DisplayName: user.DisplayName,
		Avatar: user.Avatar, Status: user.Status,
		CreatedAt: user.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt: user.UpdatedAt.Format("2006-01-02 15:04:05"),
	}, nil
}

func (s *AdminService) ForceLogout(ctx context.Context, userID, clientID string) error {
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "查询用户失败", err)
	}
	if user == nil {
		return errcode.New(errcode.NotFound, "用户不存在")
	}
	return s.repos.Refresh.RevokeAllByUser(ctx, userID, clientID, time.Now())
}

type AuditView struct {
	ID        uint64 `json:"id"`
	TenantID  string `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	UserID    string `json:"user_id"`
	Action    string `json:"action"`
	Success   bool   `json:"success"`
	Detail    string `json:"detail"`
	IP        string `json:"ip"`
	UA        string `json:"ua"`
	RequestID string `json:"request_id,omitempty"`
	JTI       string `json:"jti,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (s *AdminService) ListAudits(ctx context.Context, filter repository.AuditFilter) ([]AuditView, int64, error) {
	list, total, err := s.repos.Audit.List(ctx, filter)
	if err != nil {
		return nil, 0, errcode.Wrap(errcode.Internal, "查询审计失败", err)
	}
	out := make([]AuditView, 0, len(list))
	for _, a := range list {
		out = append(out, AuditView{
			ID: a.ID, TenantID: a.TenantID, ClientID: a.ClientID, UserID: a.UserID,
			Action: a.Action, Success: a.Success, Detail: a.Detail, IP: a.IP, UA: a.UA,
			RequestID: a.RequestID, JTI: a.JTI, DeviceID: a.DeviceID,
			CreatedAt: a.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return out, total, nil
}

type UpsertOAuthProviderRequest struct {
	Name         string   `json:"name" binding:"required"`
	Kind         string   `json:"kind"` // generic | wechat | wecom
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"userinfo_url"`
	Scopes       []string `json:"scopes"`
	Enabled      *bool    `json:"enabled"`
}

func (s *AdminService) UpsertOAuthProvider(ctx context.Context, req UpsertOAuthProviderRequest, actor string) (*model.OAuthProviderRow, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errcode.New(errcode.BadRequest, "name 不能为空")
	}
	kind := req.Kind
	if kind == "" {
		kind = "generic"
		if name == "wechat" {
			kind = "wechat"
		}
		if name == "wecom" {
			kind = "wecom"
		}
	}
	var row model.OAuthProviderRow
	err := s.repos.DB.WithContext(ctx).Where("name = ?", name).First(&row).Error
	notFound := err != nil
	if notFound {
		row = model.OAuthProviderRow{Name: name}
	}
	row.Kind = kind
	if req.ClientID != "" {
		row.ClientID = req.ClientID
	}
	if req.ClientSecret != "" {
		row.ClientSecret = req.ClientSecret
	}
	if req.AuthURL != "" {
		row.AuthURL = req.AuthURL
	}
	if req.TokenURL != "" {
		row.TokenURL = req.TokenURL
	}
	if req.UserInfoURL != "" {
		row.UserInfoURL = req.UserInfoURL
	}
	if req.Scopes != nil {
		row.Scopes = req.Scopes
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	row.Enabled = enabled
	if notFound {
		if err := s.repos.DB.WithContext(ctx).Create(&row).Error; err != nil {
			return nil, errcode.Wrap(errcode.Internal, "保存 OAuth Provider 失败", err)
		}
	} else {
		if err := s.repos.DB.WithContext(ctx).Save(&row).Error; err != nil {
			return nil, errcode.Wrap(errcode.Internal, "更新 OAuth Provider 失败", err)
		}
	}
	if s.oauthReg != nil {
		if row.Enabled && row.ClientID != "" {
			s.oauthReg.Upsert(row.Name, config.OAuthProviderConfig{
				Kind: row.Kind, ClientID: row.ClientID, ClientSecret: row.ClientSecret,
				AuthURL: row.AuthURL, TokenURL: row.TokenURL, UserInfoURL: row.UserInfoURL,
				Scopes: append([]string{}, row.Scopes...),
			})
		} else {
			s.oauthReg.Remove(row.Name)
		}
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_oauth_hot_reload", Success: true,
		Detail: "provider=" + row.Name + " enabled=" + strconv.FormatBool(row.Enabled),
		CreatedAt: time.Now(),
	})
	out := row
	out.ClientSecret = ""
	return &out, nil
}

func (s *AdminService) ListOAuthProviders(ctx context.Context) ([]model.OAuthProviderRow, error) {
	var list []model.OAuthProviderRow
	if err := s.repos.DB.WithContext(ctx).Order("name asc").Find(&list).Error; err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询 OAuth Provider 失败", err)
	}
	for i := range list {
		list[i].ClientSecret = ""
	}
	seen := map[string]bool{}
	for _, r := range list {
		seen[r.Name] = true
	}
	for name, cfg := range s.cfg.OAuth.Providers {
		if seen[name] {
			continue
		}
		list = append(list, model.OAuthProviderRow{
			Name: name, Kind: cfg.Kind, ClientID: cfg.ClientID,
			AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL, UserInfoURL: cfg.UserInfoURL,
			Scopes: cfg.Scopes, Enabled: cfg.ClientID != "",
		})
	}
	return list, nil
}

func (s *AdminService) ListUserSessions(ctx context.Context, userID, clientID string) ([]SessionView, error) {
	list, err := s.repos.Refresh.ListActiveByUser(ctx, userID, clientID)
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
		})
	}
	return out, nil
}
