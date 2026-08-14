package service

import (
	"context"
	"strings"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
)

// UserInfoClaims OIDC 兼容 userinfo 响应。
type UserInfoClaims struct {
	Sub           string   `json:"sub"`
	Name          string   `json:"name,omitempty"`
	Picture       string   `json:"picture,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	PhoneNumber   string   `json:"phone_number,omitempty"`
	PhoneVerified bool     `json:"phone_number_verified,omitempty"`
	TenantID      string   `json:"tenant_id,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	UpdatedAt     int64    `json:"updated_at,omitempty"`
}

func (s *AuthService) UserInfo(ctx context.Context, userID string) (*UserInfoClaims, error) {
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	ids, err := s.repos.Identity.ListByUserID(ctx, userID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询身份失败", err)
	}
	roles, _ := s.rolesForUser(ctx, userID, user.TenantID)
	out := &UserInfoClaims{
		Sub:       user.UserID,
		Name:      user.DisplayName,
		Picture:   user.Avatar,
		TenantID:  user.TenantID,
		Roles:     roles,
		UpdatedAt: user.UpdatedAt.Unix(),
	}
	for _, id := range ids {
		switch id.Type {
		case model.IdentityEmail:
			if out.Email == "" {
				out.Email = id.Identifier
				out.EmailVerified = id.Verified
			}
		case model.IdentityPhone:
			if out.PhoneNumber == "" {
				out.PhoneNumber = id.Identifier
				out.PhoneVerified = id.Verified
			}
		}
	}
	return out, nil
}

// OpenIDConfiguration 返回精简 OIDC Discovery 文档。
func (s *AuthService) OpenIDConfiguration(baseURL string) map[string]interface{} {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = s.cfg.Server.PublicBaseURL
	}
	if base == "" {
		base = "http://127.0.0.1" + s.cfg.Server.Addr
	}
	issuer := s.cfg.JWT.Issuer
	if issuer == "" {
		issuer = base
	}
	return map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                base + "/login",
		"token_endpoint":                        base + "/api/v1/auth/token",
		"userinfo_endpoint":                     base + "/api/v1/auth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"introspection_endpoint":                base + "/api/v1/auth/introspect",
		// RFC 7009 吊销端点；logout 仍作为 RP-initiated end_session 使用
		"revocation_endpoint":                   base + "/api/v1/auth/revoke",
		"end_session_endpoint":                  base + "/api/v1/auth/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{s.cfg.JWT.Alg},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone"},
		"claims_supported": []string{
			"sub", "name", "picture", "email", "email_verified",
			"phone_number", "phone_number_verified", "tenant_id", "roles",
			"iss", "aud", "exp", "iat", "auth_time",
		},
	}
}
