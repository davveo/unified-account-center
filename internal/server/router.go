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
	"github.com/davveo/unified-account-center/internal/pkg/tracing"
	"github.com/davveo/unified-account-center/internal/repository"
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
	Repos        *repository.Repos
	AdminToken   string
	Mode         string
}

func NewRouter(d Deps) *gin.Engine {
	if d.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery(), tracing.Middleware(), observability.Middleware(), middleware.RequestID())
	if d.Repos != nil {
		r.Use(middleware.CORS(d.Repos))
	}

	// liveness：进程存活即可
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "message": "ok", "data": gin.H{"status": "up"}})
	})
	// readiness：依赖深检
	r.GET("/readyz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		status := "up"
		checks := gin.H{}
		if d.DB != nil {
			sqlDB, err := d.DB.DB()
			if err != nil || sqlDB.PingContext(ctx) != nil {
				status = "down"
				checks["mysql"] = "down"
			} else {
				checks["mysql"] = "up"
			}
		}
		if d.Redis != nil {
			if err := d.Redis.Ping(ctx); err != nil {
				status = "down"
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
	r.GET("/.well-known/openid-configuration", d.AuthHandler.OpenIDConfiguration)
	r.GET("/api/v1/auth/jwks", func(c *gin.Context) {
		c.JSON(http.StatusOK, d.JWT.JWKS())
	})
	r.GET("/openapi.yaml", func(c *gin.Context) {
		data, err := web.OpenAPIYAML()
		if err != nil {
			c.String(http.StatusInternalServerError, "openapi missing")
			return
		}
		c.Data(http.StatusOK, "application/yaml; charset=utf-8", data)
	})
	r.GET("/docs", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`<!doctype html><html><head><title>UAC API Docs</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/></head>
<body><div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:'/openapi.yaml',dom_id:'#swagger-ui'})</script>
</body></html>`))
	})

	adminStatic, err := fs.Sub(web.AdminFS, "admin")
	if err == nil {
		// 站点根路径默认进入管理后台；未登录由 admin SPA 展示登录门
		r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/admin/") })
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

	accountStatic, err := fs.Sub(web.AccountFS, "account")
	if err == nil {
		r.GET("/account", func(c *gin.Context) { c.Redirect(http.StatusFound, "/account/") })
		r.GET("/account/", func(c *gin.Context) {
			data, err := fs.ReadFile(accountStatic, "index.html")
			if err != nil {
				c.String(http.StatusInternalServerError, "account page missing")
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
		})
		r.StaticFS("/account/static", http.FS(accountStatic))
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
			pub.GET("/saml/start", d.AuthHandler.SAMLStart)
			pub.POST("/saml/acs", d.AuthHandler.SAMLACS)
			pub.GET("/saml/metadata", d.AuthHandler.SAMLMetadata)
			pub.GET("/saml/slo", d.AuthHandler.SAMLSLO)
			pub.POST("/saml/slo", d.AuthHandler.SAMLSLO)
		}

		serverAPI := v1.Group("")
		serverAPI.Use(middleware.RequireClientSecret(d.AuthService))
		{
			serverAPI.GET("/introspect", d.AuthHandler.Introspect)
			serverAPI.POST("/introspect", d.AuthHandler.Introspect)
			serverAPI.GET("/token-check", d.AuthHandler.TokenCheck)
			serverAPI.POST("/token-check", d.AuthHandler.TokenCheck)
			serverAPI.POST("/token", d.AuthHandler.ExchangeToken)
			serverAPI.POST("/revoke", d.AuthHandler.RevokeToken)
		}

		user := v1.Group("")
		user.Use(middleware.ClientAuth(d.AuthService), middleware.UserAuth(d.JWT, d.Redis))
		{
			user.GET("/me", d.AuthHandler.Me)
		user.PATCH("/me", d.AuthHandler.UpdateMe)
		user.GET("/preferences", d.AuthHandler.GetPreferences)
		user.PATCH("/preferences", d.AuthHandler.UpdatePreferences)
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
			user.GET("/notifications", d.AuthHandler.ListNotifications)
			user.POST("/notifications/:id/read", d.AuthHandler.MarkNotificationRead)
		}

		// OIDC userinfo：仅需 Bearer（可不带 X-Client-Id）
		oidcUser := v1.Group("")
		oidcUser.Use(middleware.UserAuth(d.JWT, d.Redis))
		{
			oidcUser.GET("/userinfo", d.AuthHandler.UserInfo)
			oidcUser.POST("/userinfo", d.AuthHandler.UserInfo)
		}
	}

	adminAPI := r.Group("/api/v1/admin")
	adminAPI.POST("/login", d.AdminHandler.Login)
	adminAuthed := adminAPI.Group("")
	adminAuthed.Use(middleware.AdminAuth(d.AdminToken, d.JWT, d.Redis))
	{
		adminAuthed.GET("/me", d.AdminHandler.Me)

		// 读：viewer+
		adminAuthed.GET("/apps", d.AdminHandler.ListApps)
		adminAuthed.GET("/apps/:client_id", d.AdminHandler.GetApp)
		adminAuthed.GET("/channels", d.AdminHandler.ListChannels)
		adminAuthed.GET("/oauth-providers", d.AdminHandler.ListOAuthProviders)
		adminAuthed.GET("/users", d.AdminHandler.ListUsers)
		adminAuthed.GET("/users/:user_id/sessions", d.AdminHandler.ListUserSessions)
		adminAuthed.GET("/audits", d.AdminHandler.ListAudits)
		adminAuthed.GET("/tenants", d.AdminHandler.ListTenants)
		adminAuthed.GET("/tenants/:tenant_id", d.AdminHandler.GetTenant)
		adminAuthed.GET("/enterprise-idps", d.AdminHandler.ListIdPs)
		adminAuthed.GET("/invites", d.AdminHandler.ListInvites)
		adminAuthed.GET("/join-requests", d.AdminHandler.ListJoinRequests)
		adminAuthed.GET("/roles", d.AdminHandler.ListRoles)
		adminAuthed.GET("/dashboard", d.AdminHandler.Dashboard)
		adminAuthed.GET("/audits/export", d.AdminHandler.ExportAudits)
		adminAuthed.GET("/exports/:filename", d.AdminHandler.DownloadExport)
		adminAuthed.GET("/sms-channel", d.AdminHandler.GetSMSChannel)
		adminAuthed.GET("/jwt-keys", d.AdminHandler.GetJWTKeys)
		adminAuthed.GET("/webhooks", d.AdminHandler.ListWebhooks)
		adminAuthed.GET("/webhooks/deliveries", d.AdminHandler.ListWebhookDeliveries)

		// 写：operator+
		adminWrite := adminAuthed.Group("")
		adminWrite.Use(middleware.AdminRequire("write"))
		{
			adminWrite.POST("/apps", d.AdminHandler.CreateApp)
			adminWrite.PATCH("/apps/:client_id", d.AdminHandler.UpdateApp)
			adminWrite.POST("/apps/:client_id/rotate-secret", d.AdminHandler.RotateSecret)
			adminWrite.GET("/apps/:client_id/secret", d.AdminHandler.RevealSecret)
			adminWrite.POST("/users", d.AdminHandler.CreateUser)
			adminWrite.POST("/users/import", d.AdminHandler.ImportUsers)
			adminWrite.POST("/users/:user_id/status", d.AdminHandler.SetUserStatus)
			adminWrite.POST("/users/:user_id/force-logout", d.AdminHandler.ForceLogout)
			adminWrite.POST("/users/:user_id/reset-mfa", d.AdminHandler.ResetMFA)
			adminWrite.GET("/users/:user_id/export", d.AdminHandler.ExportUser)
			adminWrite.POST("/users/:user_id/anonymize", d.AdminHandler.AnonymizeUser)
			adminWrite.POST("/users/merge", d.AdminHandler.MergeUsers)
			adminWrite.POST("/risk/unlock", d.AdminHandler.UnlockRisk)
			adminWrite.POST("/invites", d.AdminHandler.CreateInvite)
			adminWrite.POST("/invites/:code/revoke", d.AdminHandler.RevokeInvite)
			adminWrite.POST("/join-requests/:request_id/review", d.AdminHandler.ReviewJoin)
			adminWrite.POST("/webhooks", d.AdminHandler.CreateWebhook)
			adminWrite.PATCH("/webhooks/:id", d.AdminHandler.UpdateWebhook)
			adminWrite.DELETE("/webhooks/:id", d.AdminHandler.DeleteWebhook)
			adminWrite.POST("/webhooks/:id/test", d.AdminHandler.TestWebhook)
			adminWrite.POST("/webhooks/deliveries/:id/replay", d.AdminHandler.ReplayWebhookDelivery)
		}

		// 管理：tenant_admin+ / platform
		adminMgmt := adminAuthed.Group("")
		adminMgmt.Use(middleware.AdminRequire("admin"))
		{
			adminMgmt.POST("/tenants", d.AdminHandler.CreateTenant)
			adminMgmt.PATCH("/tenants/:tenant_id", d.AdminHandler.UpdateTenant)
			adminMgmt.PUT("/enterprise-idps", d.AdminHandler.UpsertIdP)
			adminMgmt.DELETE("/enterprise-idps/:id", d.AdminHandler.DeleteIdP)
			adminMgmt.POST("/roles/assign", d.AdminHandler.AssignRole)
			adminMgmt.POST("/roles/revoke", d.AdminHandler.RevokeRole)
			adminMgmt.PUT("/oauth-providers", d.AdminHandler.UpsertOAuthProvider)
			adminMgmt.PUT("/sms-channel", d.AdminHandler.UpdateSMSChannel)
			adminMgmt.POST("/jwt-keys/rotate", d.AdminHandler.RotateJWTKeys)
			adminMgmt.POST("/jwt-keys/retire-previous", d.AdminHandler.RetireJWTPrevious)
		}
	}

	return r
}
