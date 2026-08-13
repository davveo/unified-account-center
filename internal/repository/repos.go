package repository

import (
	"context"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"gorm.io/gorm"
)

type UserRepo interface {
	Create(ctx context.Context, user *model.User) error
	FindByUserID(ctx context.Context, userID string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	List(ctx context.Context, tenantID, keyword string, limit, offset int) ([]model.User, int64, error)
}

type IdentityRepo interface {
	Create(ctx context.Context, identity *model.Identity) error
	FindByUnique(ctx context.Context, tenantID, typ, provider, identifier string) (*model.Identity, error)
	ListByUserID(ctx context.Context, userID string) ([]model.Identity, error)
	Delete(ctx context.Context, id uint64) error
	CountByUserID(ctx context.Context, userID string) (int64, error)
}

type CredentialRepo interface {
	UpsertPassword(ctx context.Context, userID, hash string) error
	FindByUserID(ctx context.Context, userID string) (*model.Credential, error)
	Save(ctx context.Context, cred *model.Credential) error
	Ensure(ctx context.Context, userID string) (*model.Credential, error)
}

type WebAuthnRepo interface {
	Create(ctx context.Context, cred *model.WebAuthnCredential) error
	ListByUserID(ctx context.Context, userID string) ([]model.WebAuthnCredential, error)
	FindByCredentialID(ctx context.Context, credID string) (*model.WebAuthnCredential, error)
	Update(ctx context.Context, cred *model.WebAuthnCredential) error
	Delete(ctx context.Context, id uint64, userID string) error
}

type KnownDeviceRepo interface {
	Upsert(ctx context.Context, d *model.KnownDevice) error
	Find(ctx context.Context, userID, clientID, deviceID string) (*model.KnownDevice, error)
}

type ChallengeRepo interface {
	Create(ctx context.Context, ch *model.AuthChallenge) error
	FindByID(ctx context.Context, challengeID string) (*model.AuthChallenge, error)
	IncrementTry(ctx context.Context, challengeID string) error
	MarkConsumed(ctx context.Context, challengeID string, at time.Time) error
}

type AppRepo interface {
	Create(ctx context.Context, app *model.App) error
	FindByClientID(ctx context.Context, clientID string) (*model.App, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]model.App, int64, error)
	Update(ctx context.Context, app *model.App) error
}

type RefreshTokenRepo interface {
	Create(ctx context.Context, token *model.RefreshToken) error
	FindByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	FindByJTI(ctx context.Context, jti string) (*model.RefreshToken, error)
	ListActiveByUser(ctx context.Context, userID, clientID string) ([]model.RefreshToken, error)
	Revoke(ctx context.Context, jti string, at time.Time) error
	RevokeAllByUser(ctx context.Context, userID, clientID string, at time.Time) error
	RevokeOthers(ctx context.Context, userID, clientID, keepJTI string, at time.Time) error
	MarkReplaced(ctx context.Context, jti, newJTI string, at time.Time) error
	ConsumeActive(ctx context.Context, jti, newJTI string, at time.Time) (bool, error)
}

type OAuthAccountRepo interface {
	Upsert(ctx context.Context, acc *model.OAuthAccount) error
	Find(ctx context.Context, provider, subject string) (*model.OAuthAccount, error)
}

type AuditFilter struct {
	TenantID string
	ClientID string
	UserID   string
	Action   string
	Success  *bool
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}

type AuditRepo interface {
	Create(ctx context.Context, log *model.AuditLog) error
	List(ctx context.Context, filter AuditFilter) ([]model.AuditLog, int64, error)
}

type Repos struct {
	DB         *gorm.DB
	User       UserRepo
	Identity   IdentityRepo
	Credential CredentialRepo
	Challenge  ChallengeRepo
	App        AppRepo
	Refresh    RefreshTokenRepo
	OAuth      OAuthAccountRepo
	Audit      AuditRepo
	WebAuthn   WebAuthnRepo
	Device     KnownDeviceRepo
	Tenant     TenantRepo
	IdP        EnterpriseIdPRepo
	Invite     InviteRepo
	Join       JoinRequestRepo
	Role       RoleRepo
}

func NewRepos(db *gorm.DB) *Repos {
	return &Repos{
		DB:         db,
		User:       NewUserRepo(db),
		Identity:   NewIdentityRepo(db),
		Credential: NewCredentialRepo(db),
		Challenge:  NewChallengeRepo(db),
		App:        NewAppRepo(db),
		Refresh:    NewRefreshTokenRepo(db),
		OAuth:      NewOAuthAccountRepo(db),
		Audit:      NewAuditRepo(db),
		WebAuthn:   NewWebAuthnRepo(db),
		Device:     NewKnownDeviceRepo(db),
		Tenant:     NewTenantRepo(db),
		IdP:        NewEnterpriseIdPRepo(db),
		Invite:     NewInviteRepo(db),
		Join:       NewJoinRequestRepo(db),
		Role:       NewRoleRepo(db),
	}
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&model.User{},
		&model.Identity{},
		&model.Credential{},
		&model.AuthChallenge{},
		&model.OAuthAccount{},
		&model.App{},
		&model.RefreshToken{},
		&model.AuditLog{},
		&model.AccessTokenBlacklist{},
		&model.OAuthProviderRow{},
		&model.WebAuthnCredential{},
		&model.KnownDevice{},
		&model.Tenant{},
		&model.EnterpriseIdP{},
		&model.Invite{},
		&model.JoinRequest{},
		&model.RoleBinding{},
		&model.PlatformSetting{},
	)
}
