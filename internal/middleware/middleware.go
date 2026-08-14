package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/pkg/response"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/gin-gonic/gin"
)

const (
	CtxRequestID = "request_id"
	CtxClientID  = "client_id"
	CtxUserID    = "user_id"
	CtxTenantID  = "tenant_id"
	CtxAccessJTI = "access_jti"
	CtxClaimsExp = "access_exp"
)

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader("X-Request-Id")
		if rid == "" {
			rid = idgen.New("req")
		}
		c.Set(CtxRequestID, rid)
		c.Writer.Header().Set("X-Request-Id", rid)
		c.Next()
	}
}

// ClientAuth 校验应用存在；若携带 X-Client-Secret 则强制验密。
func ClientAuth(auth *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientID := c.GetHeader("X-Client-Id")
		secret := c.GetHeader("X-Client-Secret")
		if clientID == "" {
			response.Fail(c, errcode.ForbiddenApp, "缺少 X-Client-Id")
			c.Abort()
			return
		}
		if secret != "" {
			if _, err := auth.VerifyClientSecret(c.Request.Context(), clientID, secret); err != nil {
				response.FailErr(c, err)
				c.Abort()
				return
			}
		} else if _, err := auth.ListMethods(c.Request.Context(), clientID); err != nil {
			response.FailErr(c, err)
			c.Abort()
			return
		}
		c.Set(CtxClientID, clientID)
		c.Next()
	}
}

// RequireClientSecret 强制要求服务端密钥。
func RequireClientSecret(auth *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientID := c.GetHeader("X-Client-Id")
		secret := c.GetHeader("X-Client-Secret")
		if _, err := auth.VerifyClientSecret(c.Request.Context(), clientID, secret); err != nil {
			response.FailErr(c, err)
			c.Abort()
			return
		}
		c.Set(CtxClientID, clientID)
		c.Next()
	}
}

func UserAuth(jwtMgr *jwtutil.Manager, redis *redisx.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			response.Fail(c, errcode.Unauthorized, "未登录")
			c.Abort()
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		claims, err := jwtMgr.ParseAccess(token)
		if err != nil {
			response.Fail(c, errcode.Unauthorized, "Token 无效")
			c.Abort()
			return
		}
		bl, err := redis.IsAccessBlacklisted(c.Request.Context(), claims.ID)
		if err != nil || bl {
			response.Fail(c, errcode.Unauthorized, "Token 已失效")
			c.Abort()
			return
		}
		if ubl, _ := redis.IsUserAccessBlacklisted(c.Request.Context(), claims.UserID); ubl {
			response.Fail(c, errcode.Unauthorized, "Token 已失效")
			c.Abort()
			return
		}
		if uv, _ := redis.GetUserVersion(c.Request.Context(), claims.UserID); uv > 0 && claims.UserVersion < uv {
			response.Fail(c, errcode.Unauthorized, "Token 已失效")
			c.Abort()
			return
		}
		clientID := c.GetHeader("X-Client-Id")
		if clientID != "" && claims.ClientID != clientID {
			response.Fail(c, errcode.ForbiddenApp, "Token 与应用不匹配")
			c.Abort()
			return
		}
		// 强制改密：仅放行改密 / step-up / me / logout
		if claims.MustChangePassword && !passwordChangeAllowed(c) {
			response.Fail(c, errcode.PasswordChangeRequired, "需要修改密码")
			c.Abort()
			return
		}
		c.Set(CtxUserID, claims.UserID)
		c.Set(CtxClientID, claims.ClientID)
		c.Set(CtxTenantID, claims.TenantID)
		c.Set(CtxAccessJTI, claims.ID)
		if claims.ExpiresAt != nil {
			c.Set(CtxClaimsExp, claims.ExpiresAt.Time)
		}
		c.Next()
	}
}

func passwordChangeAllowed(c *gin.Context) bool {
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	switch path {
	case "/api/v1/auth/password/set", "/api/v1/auth/step-up", "/api/v1/auth/me", "/api/v1/auth/logout",
		"/api/v1/auth/userinfo", "/api/v1/auth/notifications", "/api/v1/auth/notifications/:id/read",
		"/api/v1/auth/preferences":
		return true
	default:
		return strings.HasPrefix(path, "/api/v1/auth/notifications")
	}
}

func AccessTTLFromCtx(c *gin.Context) time.Duration {
	if v, ok := c.Get(CtxClaimsExp); ok {
		if t, ok := v.(time.Time); ok {
			d := time.Until(t)
			if d > 0 {
				return d
			}
		}
	}
	return time.Hour
}

// AdminAuth 管理后台鉴权：接受 X-Admin-Token，或 Bearer JWT（含 platform_admin / tenant_admin / operator / viewer）。
func AdminAuth(token string, jwtMgr *jwtutil.Manager, redis *redisx.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		got := c.GetHeader("X-Admin-Token")
		if token != "" && got != "" && got == token {
			c.Set(CtxAdminRole, "platform_admin")
			c.Set(CtxAdminTenant, "")
			c.Next()
			return
		}
		// 兼容角色 JWT
		h := c.GetHeader("Authorization")
		if jwtMgr != nil && strings.HasPrefix(h, "Bearer ") {
			tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
			claims, err := jwtMgr.ParseAccess(tok)
			if err == nil {
				if redis != nil {
					if bl, _ := redis.IsAccessBlacklisted(c.Request.Context(), claims.ID); bl {
						response.Fail(c, errcode.Unauthorized, "Token 已失效")
						c.Abort()
						return
					}
				}
				if service.HasAdminCapability(claims.Roles, "read") {
					c.Set(CtxUserID, claims.UserID)
					c.Set(CtxAdminRole, strings.Join(claims.Roles, ","))
					c.Set(CtxAdminTenant, claims.TenantID)
					c.Set(CtxTenantID, claims.TenantID)
					c.Next()
					return
				}
			}
		}
		response.Fail(c, errcode.Unauthorized, "管理 Token 无效")
		c.Abort()
	}
}

const (
	CtxAdminRole   = "admin_role"
	CtxAdminTenant = "admin_tenant"
)

// AdminRequire 在 AdminAuth 之后校验 write/admin 能力；viewer 仅能读。
func AdminRequire(need string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleRaw, _ := c.Get(CtxAdminRole)
		roles := service.ParseAdminRoles(fmt.Sprint(roleRaw))
		if service.HasAdminCapability(roles, need) {
			c.Next()
			return
		}
		response.Fail(c, errcode.ForbiddenApp, "权限不足")
		c.Abort()
	}
}

// AdminTenantFilter 非平台超管时强制使用其 JWT 租户，忽略跨租户查询参数。
// 返回 (effectiveTenantID, isPlatform)。platform 且 query 为空表示不限制租户。
func AdminTenantFilter(c *gin.Context, requested string) (string, bool) {
	roleRaw, _ := c.Get(CtxAdminRole)
	roles := service.ParseAdminRoles(fmt.Sprint(roleRaw))
	if service.IsPlatformAdmin(roles) {
		return strings.TrimSpace(requested), true
	}
	tid, _ := c.Get(CtxAdminTenant)
	s, _ := tid.(string)
	s = strings.TrimSpace(s)
	if s == "" {
		if v, ok := c.Get(CtxTenantID); ok {
			s, _ = v.(string)
		}
	}
	if s == "" {
		s = "default"
	}
	return s, false
}
