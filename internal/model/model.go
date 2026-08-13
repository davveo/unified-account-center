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
	MethodPasskey       = "passkey"
	MethodTOTP          = "totp"

	SceneLogin         = "login"
	SceneBind          = "bind"
	SceneResetPassword = "reset_password"
	SceneStepUp        = "step_up"
	SceneMerge         = "merge"
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
	MFAEnabled        bool       `gorm:"not null;default:false" json:"mfa_enabled"`
	MFABackupHashes   StringList `gorm:"type:json" json:"-"` // 一次性备份码哈希
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (Credential) TableName() string { return "credentials" }

// WebAuthnCredential Passkey 凭证。
type WebAuthnCredential struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	CredentialID string    `gorm:"size:512;uniqueIndex;not null" json:"credential_id"`
	UserID       string    `gorm:"size:64;index;not null" json:"user_id"`
	Name         string    `gorm:"size:128" json:"name"`
	PublicKey    string    `gorm:"type:text;not null" json:"-"`
	Attestation  string    `gorm:"type:text" json:"-"`
	SignCount    uint32    `gorm:"not null;default:0" json:"sign_count"`
	Transports   StringList `gorm:"type:json" json:"transports,omitempty"`
	AAGUID       string    `gorm:"size:64" json:"aaguid,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

func (WebAuthnCredential) TableName() string { return "webauthn_credentials" }

// KnownDevice 已见过的设备，用于新设备风控。
type KnownDevice struct {
	ID         uint64    `gorm:"primaryKey;autoIncrement" json:"-"`
	UserID     string    `gorm:"size:64;uniqueIndex:uk_device;not null" json:"user_id"`
	ClientID   string    `gorm:"size:64;uniqueIndex:uk_device;not null" json:"client_id"`
	DeviceID   string    `gorm:"size:128;uniqueIndex:uk_device;not null" json:"device_id"`
	Fingerprint string   `gorm:"size:128" json:"fingerprint"`
	IP         string    `gorm:"size:64" json:"ip"`
	UA         string    `gorm:"size:512" json:"ua"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (KnownDevice) TableName() string { return "known_devices" }

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
	ID               uint64     `gorm:"primaryKey;autoIncrement" json:"-"`
	ClientID         string     `gorm:"size:64;uniqueIndex;not null" json:"client_id"`
	ClientSecretHash string     `gorm:"size:255;not null" json:"-"`
	ClientSecretEnc  string     `gorm:"size:512" json:"-"` // AES 密文，供管理后台查看
	Name             string     `gorm:"size:128" json:"name"`
	TenantID         string     `gorm:"size:64;not null;default:default" json:"tenant_id"`
	AllowedMethods   StringList `gorm:"type:json;not null" json:"allowed_methods"`
	RedirectURIs     StringList `gorm:"type:json;not null" json:"redirect_uris"`
	OAuthProviders   StringList `gorm:"type:json" json:"oauth_providers"`
	AutoRegister     bool       `gorm:"not null;default:true" json:"auto_register"`
	RequirePKCE      bool       `gorm:"not null;default:false" json:"require_pkce"`
	LoginTitle       string     `gorm:"size:128" json:"login_title"`
	LogoURL          string     `gorm:"size:512" json:"logo_url"`
	ThemeColor       string     `gorm:"size:32" json:"theme_color"`
	AccessTTL        int64      `gorm:"not null;default:7200" json:"access_ttl"`
	RefreshTTL       int64      `gorm:"not null;default:2592000" json:"refresh_ttl"`
	Status           string     `gorm:"size:32;not null;default:active" json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
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
	Fingerprint      string     `gorm:"size:128" json:"fingerprint"`
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

// ---- P2: 多租户 / SSO / 邀请 / RBAC ----

const (
	TenantStatusActive   = "active"
	TenantStatusDisabled = "disabled"

	InviteStatusActive  = "active"
	InviteStatusRevoked = "revoked"

	JoinPending  = "pending"
	JoinApproved = "approved"
	JoinRejected = "rejected"

	RolePlatformAdmin = "platform_admin"
	RoleTenantAdmin   = "tenant_admin"
	RoleOperator      = "operator"
	RoleViewer        = "viewer"
	RoleUser          = "user"
)

type Tenant struct {
	ID                   uint64     `gorm:"primaryKey;autoIncrement" json:"-"`
	TenantID             string     `gorm:"size:64;uniqueIndex;not null" json:"tenant_id"`
	Name                 string     `gorm:"size:128;not null" json:"name"`
	Status               string     `gorm:"size:32;not null;default:active" json:"status"`
	MaxApps              int        `gorm:"not null;default:20" json:"max_apps"`
	DailyOTPLimit        int        `gorm:"not null;default:5000" json:"daily_otp_limit"`
	ForceSSO             bool       `gorm:"not null;default:false" json:"force_sso"`
	DisableLocalPassword bool       `gorm:"not null;default:false" json:"disable_local_password"`
	SSODomains           StringList `gorm:"type:json" json:"sso_domains"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func (Tenant) TableName() string { return "tenants" }

// EnterpriseIdP 按邮箱域名路由到 OAuth/OIDC Provider。
type EnterpriseIdP struct {
	ID         uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID   string    `gorm:"size:64;index;not null;uniqueIndex:uk_idp_domain" json:"tenant_id"`
	Domain     string    `gorm:"size:128;not null;uniqueIndex:uk_idp_domain" json:"domain"` // acme.com
	Provider   string    `gorm:"size:64;not null" json:"provider"`                         // oauth provider name
	JITEnabled bool      `gorm:"not null;default:true" json:"jit_enabled"`
	AttrMap    string    `gorm:"type:text" json:"attr_map"` // JSON: email/name/avatar keys
	Enabled    bool      `gorm:"not null;default:true" json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (EnterpriseIdP) TableName() string { return "enterprise_idps" }

type Invite struct {
	ID        uint64     `gorm:"primaryKey;autoIncrement" json:"-"`
	Code      string     `gorm:"size:64;uniqueIndex;not null" json:"code"`
	TenantID  string     `gorm:"size:64;index;not null" json:"tenant_id"`
	ClientID  string     `gorm:"size:64;index" json:"client_id"`
	Email     string     `gorm:"size:255" json:"email"`
	Phone     string     `gorm:"size:32" json:"phone"`
	MaxUses   int        `gorm:"not null;default:1" json:"max_uses"`
	UsedCount int        `gorm:"not null;default:0" json:"used_count"`
	ExpireAt  *time.Time `gorm:"index" json:"expire_at"`
	CreatedBy string     `gorm:"size:64" json:"created_by"`
	Status    string     `gorm:"size:32;not null;default:active" json:"status"`
	Note      string     `gorm:"size:255" json:"note"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func (Invite) TableName() string { return "invites" }

// JoinRequest auto_register=false 时的审批入驻。
type JoinRequest struct {
	ID         uint64    `gorm:"primaryKey;autoIncrement" json:"-"`
	RequestID  string    `gorm:"size:64;uniqueIndex;not null" json:"request_id"`
	TenantID   string    `gorm:"size:64;index;not null" json:"tenant_id"`
	ClientID   string    `gorm:"size:64;index;not null" json:"client_id"`
	Method     string    `gorm:"size:32;not null" json:"method"`
	Identity   string    `gorm:"size:255;not null" json:"identity"`
	Provider   string    `gorm:"size:64" json:"provider"`
	IdType     string    `gorm:"size:32" json:"id_type"`
	Identifier string    `gorm:"size:255" json:"identifier"`
	ProfileJSON string   `gorm:"type:text" json:"profile_json"`
	Status     string    `gorm:"size:32;not null;default:pending;index" json:"status"`
	Reviewer   string    `gorm:"size:64" json:"reviewer"`
	Note       string    `gorm:"size:255" json:"note"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (JoinRequest) TableName() string { return "join_requests" }

type RoleBinding struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"-"`
	UserID    string    `gorm:"size:64;not null;uniqueIndex:uk_role_bind" json:"user_id"`
	TenantID  string    `gorm:"size:64;not null;default:'';uniqueIndex:uk_role_bind" json:"tenant_id"` // 空=平台级
	Role      string    `gorm:"size:32;not null;uniqueIndex:uk_role_bind" json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func (RoleBinding) TableName() string { return "role_bindings" }
