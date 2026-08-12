package service

import (
	"context"
	"time"

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
	OAuthProviders []string `json:"oauth_providers"`
	AutoRegister   *bool    `json:"auto_register"`
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
	if req.OAuthProviders != nil {
		app.OAuthProviders = req.OAuthProviders
	}
	if req.AutoRegister != nil {
		app.AutoRegister = *req.AutoRegister
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

func (s *AdminService) RotateSecret(ctx context.Context, clientID string) (*RotateSecretResult, error) {
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
	app.ClientSecretHash = hash
	if err := s.repos.App.Update(ctx, app); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "轮换密钥失败", err)
	}
	_ = s.repos.DB.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("client_id = ? AND revoked_at IS NULL", clientID).
		Update("revoked_at", time.Now())
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
			CreatedAt: a.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return out, total, nil
}
