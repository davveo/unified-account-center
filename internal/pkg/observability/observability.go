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
	reqTotal      atomic.Int64
	reqErrors     atomic.Int64
	loginOK       atomic.Int64
	loginFail     atomic.Int64
	refreshOK     atomic.Int64
	refreshFail   atomic.Int64
	otpSent       atomic.Int64
	otpLimitHits  atomic.Int64
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

func IncOTPSent() {
	otpSent.Add(1)
}

func IncOTPLimitHit() {
	otpLimitHits.Add(1)
}

type Snapshot struct {
	HTTPRequests   int64   `json:"http_requests"`
	HTTPErrors     int64   `json:"http_errors"`
	LoginOK        int64   `json:"login_ok"`
	LoginFail      int64   `json:"login_fail"`
	LoginSuccessRate float64 `json:"login_success_rate"`
	RefreshOK      int64   `json:"refresh_ok"`
	RefreshFail    int64   `json:"refresh_fail"`
	OTPSent        int64   `json:"otp_sent"`
	OTPLimitHits   int64   `json:"otp_limit_hits"`
}

func MetricsSnapshot() Snapshot {
	ok := loginOK.Load()
	fail := loginFail.Load()
	total := ok + fail
	rate := 0.0
	if total > 0 {
		rate = float64(ok) / float64(total)
	}
	return Snapshot{
		HTTPRequests: reqTotal.Load(), HTTPErrors: reqErrors.Load(),
		LoginOK: ok, LoginFail: fail, LoginSuccessRate: rate,
		RefreshOK: refreshOK.Load(), RefreshFail: refreshFail.Load(),
		OTPSent: otpSent.Load(), OTPLimitHits: otpLimitHits.Load(),
	}
}

func MetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		s := MetricsSnapshot()
		body := "" +
			"# HELP uac_http_requests_total Total HTTP requests\n" +
			"# TYPE uac_http_requests_total counter\n" +
			"uac_http_requests_total " + strconv.FormatInt(s.HTTPRequests, 10) + "\n" +
			"# HELP uac_http_errors_total Total HTTP 5xx\n" +
			"# TYPE uac_http_errors_total counter\n" +
			"uac_http_errors_total " + strconv.FormatInt(s.HTTPErrors, 10) + "\n" +
			"# HELP uac_login_total Login attempts by result\n" +
			"# TYPE uac_login_total counter\n" +
			"uac_login_total{result=\"ok\"} " + strconv.FormatInt(s.LoginOK, 10) + "\n" +
			"uac_login_total{result=\"fail\"} " + strconv.FormatInt(s.LoginFail, 10) + "\n" +
			"# HELP uac_refresh_total Refresh attempts by result\n" +
			"# TYPE uac_refresh_total counter\n" +
			"uac_refresh_total{result=\"ok\"} " + strconv.FormatInt(s.RefreshOK, 10) + "\n" +
			"uac_refresh_total{result=\"fail\"} " + strconv.FormatInt(s.RefreshFail, 10) + "\n" +
			"# HELP uac_otp_sent_total OTP messages sent\n" +
			"# TYPE uac_otp_sent_total counter\n" +
			"uac_otp_sent_total " + strconv.FormatInt(s.OTPSent, 10) + "\n" +
			"# HELP uac_otp_limit_hits_total OTP daily/limit alert hits\n" +
			"# TYPE uac_otp_limit_hits_total counter\n" +
			"uac_otp_limit_hits_total " + strconv.FormatInt(s.OTPLimitHits, 10) + "\n"
		c.Data(http.StatusOK, "text/plain; version=0.0.4", []byte(body))
	}
}
