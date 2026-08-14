// Package tracing 提供 W3C traceparent 风格的轻量链路追踪。
// 不引入 OTel SDK：仅解析/透传 trace_id + span_id，并输出 span 起止日志，
// 网关或 Collector 可据此串联。服务名可用 OTEL_SERVICE_NAME 覆盖。
package tracing

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	CtxTraceID = "trace_id"
	CtxSpanID  = "span_id"

	HeaderTraceParent = "traceparent"
	HeaderTraceID     = "X-Trace-Id"
	HeaderSpanID      = "X-Span-Id"
)

func serviceName() string {
	if v := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); v != "" {
		return v
	}
	return "unified-account-center"
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", n*2)
	}
	return hex.EncodeToString(b)
}

// NewTraceID 生成 32 位十六进制 trace id。
func NewTraceID() string { return randomHex(16) }

// NewSpanID 生成 16 位十六进制 span id。
func NewSpanID() string { return randomHex(8) }

// parseTraceParent 解析 W3C traceparent：version-traceid-spanid-flags。
func parseTraceParent(v string) (traceID, parentSpanID string) {
	parts := strings.Split(strings.TrimSpace(v), "-")
	if len(parts) < 4 {
		return "", ""
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		return "", ""
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", ""
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", ""
	}
	return parts[1], parts[2]
}

// TraceIDFrom 读取当前请求的 trace id。
func TraceIDFrom(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return c.GetString(CtxTraceID)
}

// Middleware 注入 trace_id / span_id，并记录 span 起止。
func Middleware() gin.HandlerFunc {
	svc := serviceName()
	return func(c *gin.Context) {
		traceID, parentSpan := parseTraceParent(c.GetHeader(HeaderTraceParent))
		if traceID == "" {
			traceID = strings.TrimSpace(c.GetHeader(HeaderTraceID))
		}
		if len(traceID) != 32 {
			traceID = NewTraceID()
		}
		spanID := NewSpanID()
		c.Set(CtxTraceID, traceID)
		c.Set(CtxSpanID, spanID)
		c.Writer.Header().Set(HeaderTraceID, traceID)
		c.Writer.Header().Set(HeaderSpanID, spanID)

		start := time.Now()
		logSpan(map[string]interface{}{
			"msg": "span_start", "service": svc, "trace_id": traceID, "span_id": spanID,
			"parent_span_id": parentSpan, "name": c.Request.Method + " " + c.FullPath(),
		})
		c.Next()
		logSpan(map[string]interface{}{
			"msg": "span_end", "service": svc, "trace_id": traceID, "span_id": spanID,
			"name": c.Request.Method + " " + c.FullPath(), "status": c.Writer.Status(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
	}
}

func logSpan(fields map[string]interface{}) {
	b, err := json.Marshal(fields)
	if err != nil {
		return
	}
	log.Println(string(b))
}
