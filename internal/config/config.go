package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Admin     AdminConfig     `yaml:"admin"`
	Database  DatabaseConfig  `yaml:"database"`
	Redis     RedisConfig     `yaml:"redis"`
	JWT       JWTConfig       `yaml:"jwt"`
	OTP       OTPConfig       `yaml:"otp"`
	Password  PasswordConfig  `yaml:"password"`
	Captcha   CaptchaConfig   `yaml:"captcha"`
	MQ        MQConfig        `yaml:"mq"`
	SMS       SMSConfig       `yaml:"sms"`
	Email     EmailConfig     `yaml:"email"`
	OAuth     OAuthConfig     `yaml:"oauth"`
	Risk      RiskConfig      `yaml:"risk"`
	WebAuthn  WebAuthnConfig  `yaml:"webauthn"`
	Export    ExportConfig    `yaml:"export"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
}

type RiskConfig struct {
	LockAfterFailures     int    `yaml:"lock_after_failures"`       // 连续失败锁定阈值，0=10
	LockWindowSec         int    `yaml:"lock_window_sec"`           // 失败计数窗口，0=900
	LockDurationSec       int    `yaml:"lock_duration_sec"`         // 锁定时长，0=900
	RequireMFAOnNewDevice bool   `yaml:"require_mfa_on_new_device"` // 新设备强制 MFA（若已启用）
	AlertWebhookURL       string `yaml:"alert_webhook_url"`         // 发码熔断等运营告警
}

type WebAuthnConfig struct {
	RPDisplayName string   `yaml:"rp_display_name"`
	RPID          string   `yaml:"rp_id"`      // localhost / example.com
	RPOrigins     []string `yaml:"rp_origins"` // https://app.example.com
}

type AdminConfig struct {
	Token string `yaml:"token"` // 后台管理 Token，请求头 X-Admin-Token
}

type ServerConfig struct {
	Addr          string `yaml:"addr"`
	Mode          string `yaml:"mode"`
	PublicBaseURL string `yaml:"public_base_url"` // 如 https://auth.example.com，用于 OIDC discovery
}

type ExportConfig struct {
	Dir string `yaml:"dir"` // 审计导出持久化目录（本地对象存储），默认 ./data/exports
}

type DatabaseConfig struct {
	Driver  string `yaml:"driver"`
	DSN     string `yaml:"dsn"`
	MaxIdle int    `yaml:"max_idle"`
	MaxOpen int    `yaml:"max_open"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type JWTConfig struct {
	Alg            string `yaml:"alg"` // HS256 | RS256
	Secret         string `yaml:"secret"`
	Issuer         string `yaml:"issuer"`
	AccessTTL      int64  `yaml:"access_ttl"`
	RefreshTTL     int64  `yaml:"refresh_ttl"`
	PrivateKeyPath string `yaml:"private_key_path"`
	PublicKeyPath  string `yaml:"public_key_path"`
	Kid            string `yaml:"kid"`
	// 双钥滚动：旧钥只验不签（可选；也可由管理端轮换后自动落盘）
	PreviousKid            string `yaml:"previous_kid"`
	PreviousPrivateKeyPath string `yaml:"previous_private_key_path"`
	PreviousPublicKeyPath  string `yaml:"previous_public_key_path"`
}

type CaptchaConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Provider  string `yaml:"provider"` // mock | turnstile | recaptcha
	SiteKey   string `yaml:"site_key"`
	SecretKey string `yaml:"secret_key"`
}

func (c JWTConfig) AccessDuration() time.Duration {
	return time.Duration(c.AccessTTL) * time.Second
}

func (c JWTConfig) RefreshDuration() time.Duration {
	return time.Duration(c.RefreshTTL) * time.Second
}

type OTPConfig struct {
	Length                int `yaml:"length"`
	TTL                   int `yaml:"ttl"`
	ResendInterval        int `yaml:"resend_interval"`
	MaxTries              int `yaml:"max_tries"`
	DailyLimitPerIdentity int `yaml:"daily_limit_per_identity"` // 单日单身份发码上限，0=20
	DailyLimitPerIP       int `yaml:"daily_limit_per_ip"`       // 单日单 IP 发码上限，0=50
}

type PasswordConfig struct {
	MinLength           int  `yaml:"min_length"`
	RequireLetterNumber bool `yaml:"require_letter_number"`
}

type MQConfig struct {
	Enabled       bool   `yaml:"enabled"`
	NameServer    string `yaml:"name_server"`
	ProducerGroup string `yaml:"producer_group"`
	SMSTopic      string `yaml:"sms_topic"`
	EmailTopic    string `yaml:"email_topic"`
}

type SMSConfig struct {
	Provider string `yaml:"provider"`
}

type EmailConfig struct {
	Provider string `yaml:"provider"`
}

type OAuthProviderConfig struct {
	Kind         string   `yaml:"kind"` // generic | wechat | wecom
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	AuthURL      string   `yaml:"auth_url"`
	TokenURL     string   `yaml:"token_url"`
	UserInfoURL  string   `yaml:"userinfo_url"`
	Scopes       []string `yaml:"scopes"`
}

type OAuthConfig struct {
	Providers map[string]OAuthProviderConfig `yaml:"providers"`
}

type BootstrapConfig struct {
	CreateDefaultApp      bool     `yaml:"create_default_app"`
	DefaultClientID       string   `yaml:"default_client_id"`
	DefaultClientSecret   string   `yaml:"default_client_secret"`
	DefaultAllowedMethods []string `yaml:"default_allowed_methods"`
	DefaultRedirectURIs   []string `yaml:"default_redirect_uris"`
	AutoRegister          bool     `yaml:"auto_register"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Addr == "" {
		c.Server.Addr = ":8080"
	}
	if c.Server.Mode == "" {
		c.Server.Mode = "debug"
	}
	if c.Export.Dir == "" {
		c.Export.Dir = "data/exports"
	}
	// 仅开发模式填充默认 Admin Token；release 必须显式配置
	if c.Admin.Token == "" && c.Server.Mode != "release" {
		c.Admin.Token = "admin-dev-token"
	}
	if c.JWT.Alg == "" {
		c.JWT.Alg = "RS256"
	}
	if c.JWT.Kid == "" {
		c.JWT.Kid = "rsa-1"
	}
	if c.JWT.AccessTTL == 0 {
		c.JWT.AccessTTL = 7200
	}
	if c.JWT.RefreshTTL == 0 {
		c.JWT.RefreshTTL = 2592000
	}
	if c.JWT.Issuer == "" {
		c.JWT.Issuer = "unified-account-center"
	}
	if c.OTP.Length == 0 {
		c.OTP.Length = 6
	}
	if c.OTP.TTL == 0 {
		c.OTP.TTL = 300
	}
	if c.OTP.ResendInterval == 0 {
		c.OTP.ResendInterval = 60
	}
	if c.OTP.MaxTries == 0 {
		c.OTP.MaxTries = 5
	}
	if c.OTP.DailyLimitPerIdentity == 0 {
		c.OTP.DailyLimitPerIdentity = 20
	}
	if c.OTP.DailyLimitPerIP == 0 {
		c.OTP.DailyLimitPerIP = 50
	}
	if c.Captcha.Provider == "" {
		c.Captcha.Provider = "mock"
	}
	if c.Password.MinLength == 0 {
		c.Password.MinLength = 8
	}
	if c.Database.MaxIdle == 0 {
		c.Database.MaxIdle = 10
	}
	if c.Database.MaxOpen == 0 {
		c.Database.MaxOpen = 50
	}
	if c.Risk.LockAfterFailures == 0 {
		c.Risk.LockAfterFailures = 10
	}
	if c.Risk.LockWindowSec == 0 {
		c.Risk.LockWindowSec = 900
	}
	if c.Risk.LockDurationSec == 0 {
		c.Risk.LockDurationSec = 900
	}
	if c.WebAuthn.RPDisplayName == "" {
		c.WebAuthn.RPDisplayName = "Unified Account Center"
	}
	if c.WebAuthn.RPID == "" {
		c.WebAuthn.RPID = "localhost"
	}
	if len(c.WebAuthn.RPOrigins) == 0 {
		c.WebAuthn.RPOrigins = []string{"http://localhost:8080", "http://127.0.0.1:8080"}
	}
}

// ValidateForRuntime 在 release 模式下拒绝不安全的默认密钥。
func (c *Config) ValidateForRuntime() error {
	if c.Server.Mode != "release" {
		return nil
	}
	var bad []string
	if c.Admin.Token == "" || c.Admin.Token == "admin-dev-token" {
		bad = append(bad, "admin.token")
	}
	if c.JWT.Secret == "" || c.JWT.Secret == "dev-change-me-unified-account-center-secret" {
		if c.JWT.Alg == "HS256" {
			bad = append(bad, "jwt.secret")
		}
	}
	if c.Bootstrap.CreateDefaultApp &&
		(c.Bootstrap.DefaultClientSecret == "" || c.Bootstrap.DefaultClientSecret == "demo_secret_change_me") {
		bad = append(bad, "bootstrap.default_client_secret")
	}
	if len(bad) > 0 {
		return fmt.Errorf("release mode rejects insecure defaults: %s", strings.Join(bad, ", "))
	}
	return nil
}
