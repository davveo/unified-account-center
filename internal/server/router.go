package server

import (
	"context"
	"io/fs"
	"net/http"
	"time"

	"github.com/davveo/unified-account-center/internal/handler"
	"github.com/davveo/unified-account-center/internal/middleware"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/davveo/unified-account-center/internal/pkg/observability"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/davveo/unified-account-center/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Deps struct {
	AuthHandler  *handler.AuthHandler
	AdminHandler *handler.AdminHandler
	AuthService  *service.AuthService
	JWT          *jwtutil.Manager
	Redis        *redisx.Client
	DB           *gorm.DB
	AdminToken   string
	Mode         string
}

func NewRouter(d Deps) *gin.Engine {
	if d.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery(), observability.Middleware(), middleware.RequestID())

	r.GET("/healthz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		status := "up"
		checks := gin.H{}
		if d.DB != nil {
			sqlDB, err := d.DB.DB()
			if err != nil || sqlDB.PingContext(ctx) != nil {
				status = "degraded"
				checks["mysql"] = "down"
			} else {
				checks["mysql"] = "up"
			}
		}
		if d.Redis != nil {
			if err := d.Redis.Ping(ctx); err != nil {
				status = "degraded"
				checks["redis"] = "down"
			} else {
				checks["redis"] = "up"
			}
		}
		code := http.StatusOK
		if status != "up" {
			code = http.StatusServiceUnavailable
		}
		c.JSON(code, gin.H{
			"code": 0, "message": "ok", "request_id": c.GetString("request_id"),
			"data": gin.H{"status": status, "checks": checks},
		})
	})
	r.GET("/metrics", observability.MetricsHandler())
	r.GET("/.well-known/jwks.json", func(c *gin.Context) {
		c.JSON(http.StatusOK, d.JWT.JWKS())
	})
	r.GET("/api/v1/auth/jwks", func(c *gin.Context) {
		c.JSON(http.StatusOK, d.JWT.JWKS())
	})

	adminStatic, err := fs.Sub(web.AdminFS, "admin")
	if err == nil {
		r.GET("/admin", func(c *gin.Context) { c.Redirect(http.StatusFound, "/admin/") })
		r.GET("/admin/", func(c *gin.Context) {
			data, err := fs.ReadFile(adminStatic, "index.html")
			if err != nil {
				c.String(http.StatusInternalServerError, "admin page missing")
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
		})
		r.StaticFS("/admin/static", http.FS(adminStatic))
	}

	hostedStatic, err := fs.Sub(web.HostedFS, "hosted")
	if err == nil {
		r.GET("/login", func(c *gin.Context) {
			data, err := fs.ReadFile(hostedStatic, "index.html")
			if err != nil {
				c.String(http.StatusInternalServerError, "login page missing")
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
		})
		r.StaticFS("/hosted/static", http.FS(hostedStatic))
	}

	// 托管登录配置（仅需 client_id）
	r.GET("/api/v1/auth/hosted/config", d.AuthHandler.HostedConfig)

	v1 := r.Group("/api/v1/auth")
	{
		pub := v1.Group("")
		pub.Use(middleware.ClientAuth(d.AuthService))
		{
			pub.GET("/methods", d.AuthHandler.Methods)
			pub.POST("/challenge", d.AuthHandler.Challenge)
			pub.POST("/login", d.AuthHandler.Login)
			pub.POST("/sso/discover", d.AuthHandler.DiscoverSSO)
			pub.GET("/sso/discover", d.AuthHandler.DiscoverSSO)
			pub.POST("/token/refresh", d.AuthHandler.Refresh)
			pub.POST("/password/reset/start", d.AuthHandler.ResetStart)
			pub.POST("/password/reset/confirm", d.AuthHandler.ResetConfirm)
			pub.GET("/oauth/:provider/start", d.AuthHandler.OAuthStart)
			pub.GET("/oauth/:provider/callback", d.AuthHandler.OAuthCallback)
			pub.POST("/mfa/complete", d.AuthHandler.MFAComplete)
			pub.POST("/passkey/login/begin", d.AuthHandler.PasskeyLoginBegin)
			pub.POST("/passkey/login/finish", d.AuthHandler.PasskeyLoginFinish)
		}

		serverAPI := v1.Group("")
		serverAPI.Use(middleware.RequireClientSecret(d.AuthService))
		{
			serverAPI.GET("/introspect", d.AuthHandler.Introspect)
			serverAPI.POST("/introspect", d.AuthHandler.Introspect)
			serverAPI.POST("/token", d.AuthHandler.ExchangeToken)
		}

		user := v1.Group("")
		user.Use(middleware.ClientAuth(d.AuthService), middleware.UserAuth(d.JWT, d.Redis))
		{
			user.GET("/me", d.AuthHandler.Me)
			user.POST("/logout", d.AuthHandler.Logout)
			user.POST("/identities/bind", d.AuthHandler.Bind)
			user.POST("/identities/unbind", d.AuthHandler.Unbind)
			user.POST("/password/set", d.AuthHandler.SetPassword)
			user.POST("/step-up", d.AuthHandler.StepUp)
			user.POST("/hosted/code", d.AuthHandler.IssueHostedCode)
			user.GET("/sessions", d.AuthHandler.ListSessions)
			user.DELETE("/sessions/:jti", d.AuthHandler.RevokeSession)
			user.POST("/sessions/revoke-others", d.AuthHandler.RevokeOtherSessions)
			user.GET("/oauth/:provider/bind-start", d.AuthHandler.OAuthStart)
			user.GET("/mfa/status", d.AuthHandler.MFAStatus)
			user.POST("/mfa/totp/setup", d.AuthHandler.MFASetup)
			user.POST("/mfa/totp/enable", d.AuthHandler.MFAEnable)
			user.POST("/mfa/totp/disable", d.AuthHandler.MFADisable)
			user.POST("/passkey/register/begin", d.AuthHandler.PasskeyRegisterBegin)
			user.POST("/passkey/register/finish", d.AuthHandler.PasskeyRegisterFinish)
			user.GET("/passkeys", d.AuthHandler.ListPasskeys)
			user.DELETE("/passkeys/:id", d.AuthHandler.DeletePasskey)
			user.POST("/merge/start", d.AuthHandler.MergeStart)
			user.POST("/merge/confirm", d.AuthHandler.MergeConfirm)
		}
	}

	adminAPI := r.Group("/api/v1/admin")
	adminAPI.Use(middleware.AdminAuth(d.AdminToken, d.JWT, d.Redis))
	{
		adminAPI.POST("/apps", d.AdminHandler.CreateApp)
		adminAPI.GET("/apps", d.AdminHandler.ListApps)
		adminAPI.GET("/apps/:client_id", d.AdminHandler.GetApp)
		adminAPI.PATCH("/apps/:client_id", d.AdminHandler.UpdateApp)
		adminAPI.POST("/apps/:client_id/rotate-secret", d.AdminHandler.RotateSecret)
		adminAPI.GET("/apps/:client_id/secret", d.AdminHandler.RevealSecret)
		adminAPI.GET("/channels", d.AdminHandler.ListChannels)
		adminAPI.GET("/oauth-providers", d.AdminHandler.ListOAuthProviders)
		adminAPI.PUT("/oauth-providers", d.AdminHandler.UpsertOAuthProvider)
		adminAPI.GET("/users", d.AdminHandler.ListUsers)
		adminAPI.POST("/users", d.AdminHandler.CreateUser)
		adminAPI.POST("/users/:user_id/status", d.AdminHandler.SetUserStatus)
		adminAPI.POST("/users/:user_id/force-logout", d.AdminHandler.ForceLogout)
		adminAPI.GET("/users/:user_id/sessions", d.AdminHandler.ListUserSessions)
		adminAPI.POST("/users/:user_id/reset-mfa", d.AdminHandler.ResetMFA)
		adminAPI.POST("/users/merge", d.AdminHandler.MergeUsers)
		adminAPI.POST("/risk/unlock", d.AdminHandler.UnlockRisk)
		adminAPI.GET("/audits", d.AdminHandler.ListAudits)

		adminAPI.POST("/tenants", d.AdminHandler.CreateTenant)
		adminAPI.GET("/tenants", d.AdminHandler.ListTenants)
		adminAPI.GET("/tenants/:tenant_id", d.AdminHandler.GetTenant)
		adminAPI.PATCH("/tenants/:tenant_id", d.AdminHandler.UpdateTenant)
		adminAPI.PUT("/enterprise-idps", d.AdminHandler.UpsertIdP)
		adminAPI.GET("/enterprise-idps", d.AdminHandler.ListIdPs)
		adminAPI.DELETE("/enterprise-idps/:id", d.AdminHandler.DeleteIdP)
		adminAPI.POST("/invites", d.AdminHandler.CreateInvite)
		adminAPI.GET("/invites", d.AdminHandler.ListInvites)
		adminAPI.POST("/invites/:code/revoke", d.AdminHandler.RevokeInvite)
		adminAPI.GET("/join-requests", d.AdminHandler.ListJoinRequests)
		adminAPI.POST("/join-requests/:request_id/review", d.AdminHandler.ReviewJoin)
		adminAPI.POST("/roles/assign", d.AdminHandler.AssignRole)
		adminAPI.POST("/roles/revoke", d.AdminHandler.RevokeRole)
		adminAPI.GET("/roles", d.AdminHandler.ListRoles)
	}

	return r
}
