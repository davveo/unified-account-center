package sms

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/config"
)

// CloudSender 阿里云 / 腾讯云短信；凭证不全时降级为日志 mock。
type CloudSender struct {
	provider string
	cfg      config.SMSConfig
	client   *http.Client
}

func NewCloud(provider string, cfg config.SMSConfig) *CloudSender {
	return &CloudSender{provider: strings.ToLower(provider), cfg: cfg, client: &http.Client{Timeout: 8 * time.Second}}
}

func (s *CloudSender) SendOTP(ctx context.Context, phone, code, scene string) error {
	if s.cfg.AccessKeyID == "" || s.cfg.AccessKeySecret == "" {
		log.Printf("[%s-sms-fallback] phone=%s scene=%s code=%s", s.provider, phone, scene, code)
		return nil
	}
	switch s.provider {
	case "tencent":
		return s.sendTencent(ctx, phone, code)
	default:
		return s.sendAliyun(ctx, phone, code)
	}
}

func (s *CloudSender) sendAliyun(ctx context.Context, phone, code string) error {
	// 简化：调用 dysmsapi SendSms；签名按阿里云 RPC 风格
	params := map[string]string{
		"AccessKeyId":      s.cfg.AccessKeyID,
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     phone,
		"RegionId":         firstNonEmpty(s.cfg.Region, "cn-hangzhou"),
		"SignName":         s.cfg.SignName,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
		"SignatureVersion": "1.0",
		"TemplateCode":     s.cfg.TemplateCode,
		"TemplateParam":    fmt.Sprintf(`{"code":"%s"}`, code),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2017-05-25",
	}
	params["Signature"] = aliyunSign(params, s.cfg.AccessKeySecret)
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://dysmsapi.aliyuncs.com/?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("aliyun sms http %d: %s", resp.StatusCode, string(b))
	}
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	if code, _ := out["Code"].(string); code != "" && code != "OK" {
		return fmt.Errorf("aliyun sms: %s", string(b))
	}
	return nil
}

func (s *CloudSender) sendTencent(ctx context.Context, phone, code string) error {
	// 腾讯云短信较复杂；此处走可观测降级：有凭证则打结构化请求日志，真实签名可后续替换官方 SDK
	log.Printf("[tencent-sms] app_id=%s phone=%s template=%s code=%s region=%s",
		s.cfg.AppID, phone, s.cfg.TemplateCode, code, s.cfg.Region)
	_ = sha256.New // keep import for future TC3 signing
	return nil
}

func aliyunSign(params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(params[k]))
	}
	canonical := strings.Join(parts, "&")
	stringToSign := "GET&%2F&" + percentEncode(canonical)
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func percentEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
