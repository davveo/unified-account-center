package middleware

import (
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
		clientID := c.GetHeader("X-Client-Id")
		if clientID != "" && claims.ClientID != clientID {
			response.Fail(c, errcode.ForbiddenApp, "Token 与应用不匹配")
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

// AdminAuth 管理后台简易鉴权（仅接受 Header，禁止 query 传参）。
func AdminAuth(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		got := c.GetHeader("X-Admin-Token")
		if token == "" || got == "" || got != token {
			response.Fail(c, errcode.Unauthorized, "管理 Token 无效")
			c.Abort()
			return
		}
		c.Next()
	}
}
