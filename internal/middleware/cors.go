package middleware

import (
	"net/http"
	"strings"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/repository"
	"github.com/gin-gonic/gin"
)

// CORS 按应用 cors_origins 白名单回写；未配置则跳过。
func CORS(repos *repository.Repos) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		clientID := c.GetHeader("X-Client-Id")
		if origin == "" || clientID == "" || repos == nil {
			c.Next()
			return
		}
		app, err := repos.App.FindByClientID(c.Request.Context(), clientID)
		if err != nil || app == nil || len(app.CORSOrigins) == 0 {
			c.Next()
			return
		}
		allowed := false
		for _, o := range app.CORSOrigins {
			if o == "*" || strings.EqualFold(o, origin) {
				allowed = true
				break
			}
		}
		if !allowed {
			c.Next()
			return
		}
		if containsStar(app.CORSOrigins) {
			c.Header("Access-Control-Allow-Origin", "*")
		} else {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Client-Id, X-Client-Secret, X-Admin-Token, X-Request-Id, X-Trace-Id")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		_ = model.App{}
		c.Next()
	}
}

func containsStar(list model.StringList) bool {
	for _, o := range list {
		if o == "*" {
			return true
		}
	}
	return false
}
