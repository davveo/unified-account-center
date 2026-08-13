package service

import (
	"context"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	idnorm "github.com/davveo/unified-account-center/internal/pkg/identity"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
)

const adminConsoleClientID = "admin_console"

type AdminLoginRequest struct {
	Mode     string `json:"mode"` // token | password，空则按字段推断
	Token    string `json:"token"`
	Identity string `json:"identity"`
	Password string `json:"password"`
	Method   string `json:"method"` // phone_password | email_password
	TenantID string `json:"tenant_id"`
}

type AdminSession struct {
	AuthType    string   `json:"auth_type"` // token | bearer
	Token       string   `json:"token"`
	Role        string   `json:"role"`
	Roles       []string `json:"roles,omitempty"`
	UserID      string   `json:"user_id,omitempty"`
	TenantID    string   `json:"tenant_id,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	ExpiresIn   int64    `json:"expires_in,omitempty"`
}

func (s *AdminService) SetJWT(jwtMgr *jwtutil.Manager) {
	s.jwt = jwtMgr
}

// AdminLogin 管理后台登录：支持 Admin Token 或具备管理角色的账号密码。
func (s *AdminService) AdminLogin(ctx context.Context, req AdminLoginRequest) (*AdminSession, error) {
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		if strings.TrimSpace(req.Token) != "" {
			mode = "token"
		} else {
			mode = "password"
		}
	}
	switch mode {
	case "token":
		return s.loginByToken(req.Token)
	case "password":
		return s.loginByPassword(ctx, req)
	default:
		return nil, errcode.New(errcode.BadRequest, "不支持的登录方式")
	}
}

func (s *AdminService) loginByToken(token string) (*AdminSession, error) {
	got := strings.TrimSpace(token)
	if got == "" || s.cfg.Admin.Token == "" || got != s.cfg.Admin.Token {
		return nil, errcode.New(errcode.Unauthorized, "管理 Token 无效")
	}
	return &AdminSession{
		AuthType: "token",
		Token:    got,
		Role:     model.RolePlatformAdmin,
		Roles:    []string{model.RolePlatformAdmin},
	}, nil
}

func (s *AdminService) loginByPassword(ctx context.Context, req AdminLoginRequest) (*AdminSession, error) {
	if s.jwt == nil {
		return nil, errcode.New(errcode.Internal, "JWT 未配置")
	}
	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = model.MethodPhonePassword
	}
	raw := strings.TrimSpace(req.Identity)
	password := req.Password
	if raw == "" || password == "" {
		return nil, errcode.New(errcode.BadRequest, "请输入账号和密码")
	}
	tid := strings.TrimSpace(req.TenantID)
	if tid == "" {
		tid = "default"
	}

	var idType, identifier string
	switch method {
	case model.MethodPhonePassword:
		idType = model.IdentityPhone
		norm, err := idnorm.NormalizePhone(raw)
		if err != nil {
			return nil, errcode.New(errcode.BadRequest, "手机号格式不正确")
		}
		identifier = norm
	case model.MethodEmailPassword:
		idType = model.IdentityEmail
		norm, err := idnorm.NormalizeEmail(raw)
		if err != nil {
			return nil, errcode.New(errcode.BadRequest, "邮箱格式不正确")
		}
		identifier = norm
	default:
		return nil, errcode.New(errcode.BadRequest, "仅支持手机号/邮箱密码登录")
	}

	ident, err := s.repos.Identity.FindByUnique(ctx, tid, idType, "", identifier)
	if err != nil || ident == nil {
		return nil, errcode.New(errcode.Unauthorized, "账号或密码错误")
	}
	user, err := s.repos.User.FindByUserID(ctx, ident.UserID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.Unauthorized, "账号或密码错误")
	}
	if user.Status == model.UserStatusDisabled {
		return nil, errcode.New(errcode.ForbiddenApp, "账号已禁用")
	}
	cred, err := s.repos.Credential.FindByUserID(ctx, user.UserID)
	if err != nil || cred == nil || cred.PasswordHash == "" {
		return nil, errcode.New(errcode.Unauthorized, "账号或密码错误")
	}
	ok, err := crypto.VerifyPassword(cred.PasswordHash, password)
	if err != nil || !ok {
		return nil, errcode.New(errcode.Unauthorized, "账号或密码错误")
	}

	roles, scope := s.rolesForAdminUser(ctx, user.UserID, user.TenantID)
	if !HasAdminCapability(roles, "read") {
		return nil, errcode.New(errcode.ForbiddenApp, "该账号无管理后台权限")
	}

	ttl := time.Duration(s.cfg.JWT.AccessTTL) * time.Second
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}
	tok, _, exp, err := s.jwt.IssueAccess(user.UserID, adminConsoleClientID, user.TenantID, ttl, roles, scope)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "签发 Token 失败", err)
	}

	primary := roles[0]
	for _, r := range roles {
		if r == model.RolePlatformAdmin {
			primary = r
			break
		}
		if r == model.RoleTenantAdmin {
			primary = r
		}
	}

	return &AdminSession{
		AuthType:    "bearer",
		Token:       tok,
		Role:        primary,
		Roles:       roles,
		UserID:      user.UserID,
		TenantID:    user.TenantID,
		DisplayName: user.DisplayName,
		ExpiresIn:   int64(exp.Sub(time.Now()).Seconds()),
	}, nil
}

func (s *AdminService) rolesForAdminUser(ctx context.Context, userID, tenantID string) ([]string, string) {
	list, err := s.repos.Role.ListByUser(ctx, userID)
	if err != nil || len(list) == 0 {
		return []string{model.RoleUser}, "user"
	}
	roles := make([]string, 0, len(list))
	for _, b := range list {
		if b.TenantID == "" || b.TenantID == tenantID || b.Role == model.RolePlatformAdmin {
			roles = append(roles, b.Role)
		}
	}
	if len(roles) == 0 {
		roles = []string{model.RoleUser}
	}
	return roles, roleScopes(roles)
}

// AdminMe 返回当前管理会话信息（由中间件注入上下文）。
func (s *AdminService) AdminMe(ctx context.Context, role, userID, tenantID string) *AdminSession {
	roles := []string{}
	if role != "" {
		for _, p := range strings.Split(role, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				roles = append(roles, p)
			}
		}
	}
	primary := ""
	if len(roles) > 0 {
		primary = roles[0]
	}
	authType := "token"
	if userID != "" {
		authType = "bearer"
	}
	sess := &AdminSession{
		AuthType: authType,
		Role:     primary,
		Roles:    roles,
		UserID:   userID,
		TenantID: tenantID,
	}
	if userID != "" {
		if u, err := s.repos.User.FindByUserID(ctx, userID); err == nil && u != nil {
			sess.DisplayName = u.DisplayName
			if sess.TenantID == "" {
				sess.TenantID = u.TenantID
			}
		}
	}
	return sess
}
