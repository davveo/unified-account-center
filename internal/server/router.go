package server

import (
	"io/fs"
	"net/http"

	"github.com/davveo/unified-account-center/internal/handler"
	"github.com/davveo/unified-account-center/internal/middleware"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/davveo/unified-account-center/web"
	"github.com/gin-gonic/gin"
)

type Deps struct {
	AuthHandler  *handler.AuthHandler
	AdminHandler *handler.AdminHandler
	AuthService  *service.AuthService
	JWT          *jwtutil.Manager
	Redis        *redisx.Client
	AdminToken   string
	Mode         string
}

func NewRouter(d Deps) *gin.Engine {
	if d.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery(), gin.Logger(), middleware.RequestID())

	r.GET("/healthz", d.AuthHandler.Health)

	// 管理后台页面
	adminStatic, err := fs.Sub(web.AdminFS, "admin")
	if err == nil {
		r.GET("/admin", func(c *gin.Context) {
			c.Redirect(http.StatusFound, "/admin/")
		})
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

	v1 := r.Group("/api/v1/auth")
	{
		pub := v1.Group("")
		pub.Use(middleware.ClientAuth(d.AuthService))
		{
			pub.GET("/methods", d.AuthHandler.Methods)
			pub.POST("/challenge", d.AuthHandler.Challenge)
			pub.POST("/login", d.AuthHandler.Login)
			pub.POST("/token/refresh", d.AuthHandler.Refresh)
			pub.POST("/password/reset/start", d.AuthHandler.ResetStart)
			pub.POST("/password/reset/confirm", d.AuthHandler.ResetConfirm)
			pub.GET("/oauth/:provider/start", d.AuthHandler.OAuthStart)
			pub.GET("/oauth/:provider/callback", d.AuthHandler.OAuthCallback)
			pub.GET("/introspect", d.AuthHandler.Introspect)
			pub.POST("/introspect", d.AuthHandler.Introspect)
		}

		user := v1.Group("")
		user.Use(middleware.ClientAuth(d.AuthService), middleware.UserAuth(d.JWT, d.Redis))
		{
			user.GET("/me", d.AuthHandler.Me)
			user.POST("/logout", d.AuthHandler.Logout)
			user.POST("/identities/bind", d.AuthHandler.Bind)
			user.POST("/identities/unbind", d.AuthHandler.Unbind)
			user.POST("/password/set", d.AuthHandler.SetPassword)
		}
	}

	adminAPI := r.Group("/api/v1/admin")
	adminAPI.Use(middleware.AdminAuth(d.AdminToken))
	{
		adminAPI.POST("/apps", d.AdminHandler.CreateApp)
		adminAPI.GET("/apps", d.AdminHandler.ListApps)
		adminAPI.GET("/apps/:client_id", d.AdminHandler.GetApp)
		adminAPI.GET("/channels", d.AdminHandler.ListChannels)
	}

	return r
}
