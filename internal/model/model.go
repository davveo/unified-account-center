package model

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"

	IdentityPhone = "phone"
	IdentityEmail = "email"
	IdentityOAuth = "oauth"

	MethodPhoneOTP      = "phone_otp"
	MethodPhonePassword = "phone_password"
	MethodEmailOTP      = "email_otp"
	MethodEmailPassword = "email_password"
	MethodOAuth2        = "oauth2"

	SceneLogin         = "login"
	SceneBind          = "bind"
	SceneResetPassword = "reset_password"
	SceneStepUp        = "step_up"
)

type User struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"-"`
	UserID      string    `gorm:"size:64;uniqueIndex;not null" json:"user_id"`
	TenantID    string    `gorm:"size:64;index;not null;default:default" json:"tenant_id"`
	DisplayName string    `gorm:"size:128" json:"display_name"`
	Avatar      string    `gorm:"size:512" json:"avatar"`
	Status      string    `gorm:"size:32;not null;default:active" json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (User) TableName() string { return "users" }

type Identity struct {
	ID         uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID   string    `gorm:"size:64;not null;default:default;uniqueIndex:uk_identity" json:"tenant_id"`
	UserID     string    `gorm:"size:64;index;not null" json:"user_id"`
	Type       string    `gorm:"size:32;not null;uniqueIndex:uk_identity" json:"type"`
	Provider   string    `gorm:"size:64;not null;default:'';uniqueIndex:uk_identity" json:"provider"`
	Identifier string    `gorm:"size:255;not null;uniqueIndex:uk_identity" json:"identifier"`
	Verified   bool      `gorm:"not null;default:false" json:"verified"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (Identity) TableName() string { return "identities" }

type Credential struct {
	ID                uint64     `gorm:"primaryKey;autoIncrement" json:"-"`
	UserID            string     `gorm:"size:64;uniqueIndex;not null" json:"user_id"`
	PasswordHash      string     `gorm:"size:255" json:"-"`
	PasswordUpdatedAt *time.Time `json:"password_updated_at,omitempty"`
	MFASecret         string     `gorm:"size:255" json:"-"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (Credential) TableName() string { return "credentials" }

type AuthChallenge struct {
	ID          uint64     `gorm:"primaryKey;autoIncrement" json:"-"`
	ChallengeID string     `gorm:"size:64;uniqueIndex;not null" json:"challenge_id"`
	ClientID    string     `gorm:"size:64;index;not null" json:"client_id"`
	TenantID    string     `gorm:"size:64;not null;default:default" json:"tenant_id"`
	Method      string     `gorm:"size:32;not null" json:"method"`
	Scene       string     `gorm:"size:32;not null" json:"scene"`
	Identity    string     `gorm:"size:255;not null" json:"identity"`
	CodeHash    string     `gorm:"size:128;not null" json:"-"`
	TryCount    int        `gorm:"not null;default:0" json:"try_count"`
	ExpireAt    time.Time  `gorm:"index;not null" json:"expire_at"`
	ConsumedAt  *time.Time `json:"consumed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (AuthChallenge) TableName() string { return "auth_challenges" }

type OAuthAccount struct {
	ID              uint64    `gorm:"primaryKey;autoIncrement" json:"-"`
	UserID          string    `gorm:"size:64;index;not null" json:"user_id"`
	Provider        string    `gorm:"size:64;not null;uniqueIndex:uk_oauth" json:"provider"`
	Subject         string    `gorm:"size:255;not null;uniqueIndex:uk_oauth" json:"subject"`
	AccessTokenEnc  string    `gorm:"type:text" json:"-"`
	RefreshTokenEnc string    `gorm:"type:text" json:"-"`
	ProfileJSON     string    `gorm:"type:text" json:"profile_json,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (OAuthAccount) TableName() string { return "oauth_accounts" }

type StringList []string

func (s StringList) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	return string(b), err
}

func (s *StringList) Scan(value interface{}) error {
	if value == nil {
		*s = StringList{}
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return nil
	}
	return json.Unmarshal(bytes, s)
}

type App struct {
	ID              uint64     `gorm:"primaryKey;autoIncrement" json:"-"`
	ClientID        string     `gorm:"size:64;uniqueIndex;not null" json:"client_id"`
	ClientSecretHash string    `gorm:"size:255;not null" json:"-"`
	Name            string     `gorm:"size:128" json:"name"`
	TenantID        string     `gorm:"size:64;not null;default:default" json:"tenant_id"`
	AllowedMethods  StringList `gorm:"type:json;not null" json:"allowed_methods"`
	RedirectURIs    StringList `gorm:"type:json;not null" json:"redirect_uris"`
	OAuthProviders  StringList `gorm:"type:json" json:"oauth_providers"`
	AutoRegister    bool       `gorm:"not null;default:true" json:"auto_register"`
	RequirePKCE     bool       `gorm:"not null;default:false" json:"require_pkce"`
	LoginTitle      string     `gorm:"size:128" json:"login_title"`
	LogoURL         string     `gorm:"size:512" json:"logo_url"`
	ThemeColor      string     `gorm:"size:32" json:"theme_color"`
	AccessTTL       int64      `gorm:"not null;default:7200" json:"access_ttl"`
	RefreshTTL      int64      `gorm:"not null;default:2592000" json:"refresh_ttl"`
	Status          string     `gorm:"size:32;not null;default:active" json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// OAuthProviderRow 平台级 OAuth Provider 配置（支持后台热更新）。
type OAuthProviderRow struct {
	ID           uint64     `gorm:"primaryKey;autoIncrement" json:"-"`
	Name         string     `gorm:"size:64;uniqueIndex;not null" json:"name"`
	Kind         string     `gorm:"size:32;not null;default:generic" json:"kind"` // generic | wechat | wecom
	ClientID     string     `gorm:"size:255" json:"client_id"`
	ClientSecret string     `gorm:"size:255" json:"-"`
	AuthURL      string     `gorm:"size:512" json:"auth_url"`
	TokenURL     string     `gorm:"size:512" json:"token_url"`
	UserInfoURL  string     `gorm:"size:512" json:"userinfo_url"`
	Scopes       StringList `gorm:"type:json" json:"scopes"`
	Enabled      bool       `gorm:"not null;default:true" json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (OAuthProviderRow) TableName() string { return "oauth_provider_configs" }

func (App) TableName() string { return "apps" }

type RefreshToken struct {
	ID               uint64     `gorm:"primaryKey;autoIncrement" json:"-"`
	JTI              string     `gorm:"size:64;uniqueIndex;not null" json:"jti"`
	TokenHash        string     `gorm:"size:128;uniqueIndex;not null" json:"-"`
	UserID           string     `gorm:"size:64;index;not null" json:"user_id"`
	ClientID         string     `gorm:"size:64;index;not null" json:"client_id"`
	DeviceID         string     `gorm:"size:128" json:"device_id"`
	IP               string     `gorm:"size:64" json:"ip"`
	UA               string     `gorm:"size:512" json:"ua"`
	ExpireAt         time.Time  `gorm:"index;not null" json:"expire_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	ReplacedByJTI    string     `gorm:"size:64" json:"replaced_by_jti,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

func (RefreshToken) TableName() string { return "refresh_tokens" }

type AuditLog struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID  string    `gorm:"size:64;index" json:"tenant_id"`
	ClientID  string    `gorm:"size:64;index" json:"client_id"`
	UserID    string    `gorm:"size:64;index" json:"user_id"`
	Action    string    `gorm:"size:64;not null" json:"action"`
	Success   bool      `gorm:"not null" json:"success"`
	Detail    string    `gorm:"type:text" json:"detail"`
	IP        string    `gorm:"size:64" json:"ip"`
	UA        string    `gorm:"size:512" json:"ua"`
	CreatedAt time.Time `json:"created_at"`
}

func (AuditLog) TableName() string { return "audit_logs" }

type AccessTokenBlacklist struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement"`
	JTI       string    `gorm:"size:64;uniqueIndex;not null"`
	ExpireAt  time.Time `gorm:"index;not null"`
	CreatedAt time.Time
}

func (AccessTokenBlacklist) TableName() string { return "access_token_blacklist" }
