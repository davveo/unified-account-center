package config

import (
	"fmt"
	"os"
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
	MQ        MQConfig        `yaml:"mq"`
	SMS       SMSConfig       `yaml:"sms"`
	Email     EmailConfig     `yaml:"email"`
	OAuth     OAuthConfig     `yaml:"oauth"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
}

type AdminConfig struct {
	Token string `yaml:"token"` // 后台管理 Token，请求头 X-Admin-Token
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
	Mode string `yaml:"mode"`
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
	Secret     string `yaml:"secret"`
	Issuer     string `yaml:"issuer"`
	AccessTTL  int64  `yaml:"access_ttl"`
	RefreshTTL int64  `yaml:"refresh_ttl"`
}

func (c JWTConfig) AccessDuration() time.Duration {
	return time.Duration(c.AccessTTL) * time.Second
}

func (c JWTConfig) RefreshDuration() time.Duration {
	return time.Duration(c.RefreshTTL) * time.Second
}

type OTPConfig struct {
	Length         int `yaml:"length"`
	TTL            int `yaml:"ttl"`
	ResendInterval int `yaml:"resend_interval"`
	MaxTries       int `yaml:"max_tries"`
}

type PasswordConfig struct {
	MinLength            int  `yaml:"min_length"`
	RequireLetterNumber  bool `yaml:"require_letter_number"`
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
	CreateDefaultApp       bool     `yaml:"create_default_app"`
	DefaultClientID        string   `yaml:"default_client_id"`
	DefaultClientSecret    string   `yaml:"default_client_secret"`
	DefaultAllowedMethods  []string `yaml:"default_allowed_methods"`
	DefaultRedirectURIs    []string `yaml:"default_redirect_uris"`
	AutoRegister           bool     `yaml:"auto_register"`
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
	if c.Admin.Token == "" {
		c.Admin.Token = "admin-dev-token"
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
	if c.Password.MinLength == 0 {
		c.Password.MinLength = 8
	}
	if c.Database.MaxIdle == 0 {
		c.Database.MaxIdle = 10
	}
	if c.Database.MaxOpen == 0 {
		c.Database.MaxOpen = 50
	}
}
