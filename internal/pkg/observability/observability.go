package observability

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	reqTotal    atomic.Int64
	reqErrors   atomic.Int64
	loginOK     atomic.Int64
	loginFail   atomic.Int64
	refreshOK   atomic.Int64
	refreshFail atomic.Int64
)

func InitLogger(mode string) {
	_ = mode
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
}

func logJSON(fields map[string]interface{}) {
	b, err := json.Marshal(fields)
	if err != nil {
		return
	}
	log.Println(string(b))
}

func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		reqTotal.Add(1)
		status := c.Writer.Status()
		if status >= 500 {
			reqErrors.Add(1)
		}
		logJSON(map[string]interface{}{
			"msg":        "http_request",
			"method":     c.Request.Method,
			"path":       c.FullPath(),
			"status":     status,
			"latency_ms": time.Since(start).Milliseconds(),
			"request_id": c.GetString("request_id"),
			"client_ip":  c.ClientIP(),
		})
	}
}

func IncLogin(ok bool) {
	if ok {
		loginOK.Add(1)
	} else {
		loginFail.Add(1)
	}
}

func IncRefresh(ok bool) {
	if ok {
		refreshOK.Add(1)
	} else {
		refreshFail.Add(1)
	}
}

func MetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		body := "" +
			"# HELP uac_http_requests_total Total HTTP requests\n" +
			"# TYPE uac_http_requests_total counter\n" +
			"uac_http_requests_total " + strconv.FormatInt(reqTotal.Load(), 10) + "\n" +
			"# HELP uac_http_errors_total Total HTTP 5xx\n" +
			"# TYPE uac_http_errors_total counter\n" +
			"uac_http_errors_total " + strconv.FormatInt(reqErrors.Load(), 10) + "\n" +
			"# HELP uac_login_total Login attempts by result\n" +
			"# TYPE uac_login_total counter\n" +
			"uac_login_total{result=\"ok\"} " + strconv.FormatInt(loginOK.Load(), 10) + "\n" +
			"uac_login_total{result=\"fail\"} " + strconv.FormatInt(loginFail.Load(), 10) + "\n" +
			"# HELP uac_refresh_total Refresh attempts by result\n" +
			"# TYPE uac_refresh_total counter\n" +
			"uac_refresh_total{result=\"ok\"} " + strconv.FormatInt(refreshOK.Load(), 10) + "\n" +
			"uac_refresh_total{result=\"fail\"} " + strconv.FormatInt(refreshFail.Load(), 10) + "\n"
		c.Data(http.StatusOK, "text/plain; version=0.0.4", []byte(body))
	}
}
