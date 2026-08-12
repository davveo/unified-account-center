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
	List(ctx context.Context, limit, offset int) ([]model.App, int64, error)
	Update(ctx context.Context, app *model.App) error
}

type RefreshTokenRepo interface {
	Create(ctx context.Context, token *model.RefreshToken) error
	FindByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	Revoke(ctx context.Context, jti string, at time.Time) error
	RevokeAllByUser(ctx context.Context, userID, clientID string, at time.Time) error
	MarkReplaced(ctx context.Context, jti, newJTI string, at time.Time) error
}

type OAuthAccountRepo interface {
	Upsert(ctx context.Context, acc *model.OAuthAccount) error
	Find(ctx context.Context, provider, subject string) (*model.OAuthAccount, error)
}

type AuditRepo interface {
	Create(ctx context.Context, log *model.AuditLog) error
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
	)
}
