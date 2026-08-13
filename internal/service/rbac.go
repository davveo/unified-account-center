package service

import (
	"context"
	"strings"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
)

var knownRoles = map[string]struct{}{
	model.RolePlatformAdmin: {},
	model.RoleTenantAdmin:   {},
	model.RoleOperator:      {},
	model.RoleViewer:        {},
	model.RoleUser:          {},
}

// roleScopes 将角色映射为粗粒度 scope（不做细粒度 ABAC）。
func roleScopes(roles []string) string {
	set := map[string]struct{}{}
	for _, r := range roles {
		switch r {
		case model.RolePlatformAdmin:
			set["admin:*"] = struct{}{}
			set["read:*"] = struct{}{}
			set["write:*"] = struct{}{}
		case model.RoleTenantAdmin:
			set["admin:tenant"] = struct{}{}
			set["read:tenant"] = struct{}{}
			set["write:tenant"] = struct{}{}
		case model.RoleOperator:
			set["read:tenant"] = struct{}{}
			set["write:users"] = struct{}{}
		case model.RoleViewer:
			set["read:tenant"] = struct{}{}
		default:
			set["user"] = struct{}{}
		}
	}
	parts := make([]string, 0, len(set))
	for k := range set {
		parts = append(parts, k)
	}
	return strings.Join(parts, " ")
}

func (s *AuthService) rolesForUser(ctx context.Context, userID, tenantID string) ([]string, string) {
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

type AssignRoleRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role" binding:"required"`
}

func (s *AdminService) AssignRole(ctx context.Context, req AssignRoleRequest) error {
	role := strings.TrimSpace(req.Role)
	if _, ok := knownRoles[role]; !ok {
		return errcode.New(errcode.BadRequest, "未知角色")
	}
	tid := strings.TrimSpace(req.TenantID)
	if role == model.RolePlatformAdmin {
		tid = ""
	}
	user, err := s.repos.User.FindByUserID(ctx, req.UserID)
	if err != nil || user == nil {
		return errcode.New(errcode.NotFound, "用户不存在")
	}
	if tid == "" && role != model.RolePlatformAdmin {
		tid = user.TenantID
	}
	return s.repos.Role.Upsert(ctx, &model.RoleBinding{
		UserID: req.UserID, TenantID: tid, Role: role,
	})
}

func (s *AdminService) RevokeRole(ctx context.Context, userID, tenantID, role string) error {
	return s.repos.Role.Delete(ctx, userID, tenantID, role)
}

func (s *AdminService) ListRoles(ctx context.Context, tenantID string, limit, offset int) ([]model.RoleBinding, int64, error) {
	return s.repos.Role.List(ctx, tenantID, limit, offset)
}

func (s *AdminService) ListUserRoles(ctx context.Context, userID string) ([]model.RoleBinding, error) {
	return s.repos.Role.ListByUser(ctx, userID)
}

// HasAdminCapability 判断角色集合是否具备管理能力。
func HasAdminCapability(roles []string, need string) bool {
	for _, r := range roles {
		if r == model.RolePlatformAdmin {
			return true
		}
		switch need {
		case "read":
			if r == model.RoleTenantAdmin || r == model.RoleOperator || r == model.RoleViewer {
				return true
			}
		case "write":
			if r == model.RoleTenantAdmin || r == model.RoleOperator {
				return true
			}
		case "admin":
			if r == model.RoleTenantAdmin {
				return true
			}
		}
	}
	return false
}
