package repository

import (
	"context"
	"errors"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"gorm.io/gorm"
)

type userRepo struct{ db *gorm.DB }

func NewUserRepo(db *gorm.DB) UserRepo { return &userRepo{db: db} }

func (r *userRepo) Create(ctx context.Context, user *model.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepo) FindByUserID(ctx context.Context, userID string) (*model.User, error) {
	var u model.User
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &u, err
}

func (r *userRepo) Update(ctx context.Context, user *model.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *userRepo) List(ctx context.Context, tenantID, keyword string, limit, offset int) ([]model.User, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	q := r.db.WithContext(ctx).Model(&model.User{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	if keyword != "" {
		like := "%" + keyword + "%"
		q = q.Where("user_id LIKE ? OR display_name LIKE ?", like, like)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.User
	err := q.Order("id desc").Limit(limit).Offset(offset).Find(&list).Error
	return list, total, err
}

type identityRepo struct{ db *gorm.DB }

func NewIdentityRepo(db *gorm.DB) IdentityRepo { return &identityRepo{db: db} }

func (r *identityRepo) Create(ctx context.Context, identity *model.Identity) error {
	return r.db.WithContext(ctx).Create(identity).Error
}

func (r *identityRepo) FindByUnique(ctx context.Context, tenantID, typ, provider, identifier string) (*model.Identity, error) {
	var idn model.Identity
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND type = ? AND provider = ? AND identifier = ?", tenantID, typ, provider, identifier).
		First(&idn).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &idn, err
}

func (r *identityRepo) ListByUserID(ctx context.Context, userID string) ([]model.Identity, error) {
	var list []model.Identity
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&list).Error
	return list, err
}

func (r *identityRepo) Delete(ctx context.Context, id uint64) error {
	return r.db.WithContext(ctx).Delete(&model.Identity{}, id).Error
}

func (r *identityRepo) CountByUserID(ctx context.Context, userID string) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&model.Identity{}).Where("user_id = ?", userID).Count(&n).Error
	return n, err
}

type credentialRepo struct{ db *gorm.DB }

func NewCredentialRepo(db *gorm.DB) CredentialRepo { return &credentialRepo{db: db} }

func (r *credentialRepo) UpsertPassword(ctx context.Context, userID, hash string) error {
	now := time.Now()
	var existing model.Credential
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(&model.Credential{
			UserID:            userID,
			PasswordHash:      hash,
			PasswordUpdatedAt: &now,
		}).Error
	}
	if err != nil {
		return err
	}
	existing.PasswordHash = hash
	existing.PasswordUpdatedAt = &now
	return r.db.WithContext(ctx).Save(&existing).Error
}

func (r *credentialRepo) FindByUserID(ctx context.Context, userID string) (*model.Credential, error) {
	var c model.Credential
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}

func (r *credentialRepo) Save(ctx context.Context, cred *model.Credential) error {
	return r.db.WithContext(ctx).Save(cred).Error
}

func (r *credentialRepo) Ensure(ctx context.Context, userID string) (*model.Credential, error) {
	c, err := r.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if c != nil {
		return c, nil
	}
	c = &model.Credential{UserID: userID}
	if err := r.db.WithContext(ctx).Create(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

type webAuthnRepo struct{ db *gorm.DB }

func NewWebAuthnRepo(db *gorm.DB) WebAuthnRepo { return &webAuthnRepo{db: db} }

func (r *webAuthnRepo) Create(ctx context.Context, cred *model.WebAuthnCredential) error {
	return r.db.WithContext(ctx).Create(cred).Error
}

func (r *webAuthnRepo) ListByUserID(ctx context.Context, userID string) ([]model.WebAuthnCredential, error) {
	var list []model.WebAuthnCredential
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("id desc").Find(&list).Error
	return list, err
}

func (r *webAuthnRepo) FindByCredentialID(ctx context.Context, credID string) (*model.WebAuthnCredential, error) {
	var c model.WebAuthnCredential
	err := r.db.WithContext(ctx).Where("credential_id = ?", credID).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}

func (r *webAuthnRepo) Update(ctx context.Context, cred *model.WebAuthnCredential) error {
	return r.db.WithContext(ctx).Save(cred).Error
}

func (r *webAuthnRepo) Delete(ctx context.Context, id uint64, userID string) error {
	return r.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&model.WebAuthnCredential{}).Error
}

type knownDeviceRepo struct{ db *gorm.DB }

func NewKnownDeviceRepo(db *gorm.DB) KnownDeviceRepo { return &knownDeviceRepo{db: db} }

func (r *knownDeviceRepo) Upsert(ctx context.Context, d *model.KnownDevice) error {
	var existing model.KnownDevice
	err := r.db.WithContext(ctx).Where("user_id = ? AND client_id = ? AND device_id = ?", d.UserID, d.ClientID, d.DeviceID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(d).Error
	}
	if err != nil {
		return err
	}
	existing.Fingerprint = d.Fingerprint
	existing.IP = d.IP
	existing.UA = d.UA
	return r.db.WithContext(ctx).Save(&existing).Error
}

func (r *knownDeviceRepo) Find(ctx context.Context, userID, clientID, deviceID string) (*model.KnownDevice, error) {
	var d model.KnownDevice
	err := r.db.WithContext(ctx).Where("user_id = ? AND client_id = ? AND device_id = ?", userID, clientID, deviceID).First(&d).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &d, err
}

type challengeRepo struct{ db *gorm.DB }

func NewChallengeRepo(db *gorm.DB) ChallengeRepo { return &challengeRepo{db: db} }

func (r *challengeRepo) Create(ctx context.Context, ch *model.AuthChallenge) error {
	return r.db.WithContext(ctx).Create(ch).Error
}

func (r *challengeRepo) FindByID(ctx context.Context, challengeID string) (*model.AuthChallenge, error) {
	var ch model.AuthChallenge
	err := r.db.WithContext(ctx).Where("challenge_id = ?", challengeID).First(&ch).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &ch, err
}

func (r *challengeRepo) IncrementTry(ctx context.Context, challengeID string) error {
	return r.db.WithContext(ctx).Model(&model.AuthChallenge{}).
		Where("challenge_id = ?", challengeID).
		UpdateColumn("try_count", gorm.Expr("try_count + 1")).Error
}

func (r *challengeRepo) MarkConsumed(ctx context.Context, challengeID string, at time.Time) error {
	return r.db.WithContext(ctx).Model(&model.AuthChallenge{}).
		Where("challenge_id = ?", challengeID).
		Update("consumed_at", at).Error
}

type appRepo struct{ db *gorm.DB }

func NewAppRepo(db *gorm.DB) AppRepo { return &appRepo{db: db} }

func (r *appRepo) Create(ctx context.Context, app *model.App) error {
	return r.db.WithContext(ctx).Create(app).Error
}

func (r *appRepo) FindByClientID(ctx context.Context, clientID string) (*model.App, error) {
	var app model.App
	err := r.db.WithContext(ctx).Where("client_id = ?", clientID).First(&app).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &app, err
}

func (r *appRepo) List(ctx context.Context, tenantID string, limit, offset int) ([]model.App, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	q := r.db.WithContext(ctx).Model(&model.App{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.App
	err := q.Order("id desc").Limit(limit).Offset(offset).Find(&list).Error
	return list, total, err
}

func (r *appRepo) Update(ctx context.Context, app *model.App) error {
	return r.db.WithContext(ctx).Save(app).Error
}

type refreshTokenRepo struct{ db *gorm.DB }

func NewRefreshTokenRepo(db *gorm.DB) RefreshTokenRepo { return &refreshTokenRepo{db: db} }

func (r *refreshTokenRepo) Create(ctx context.Context, token *model.RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *refreshTokenRepo) FindByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	var t model.RefreshToken
	err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &t, err
}

func (r *refreshTokenRepo) FindByJTI(ctx context.Context, jti string) (*model.RefreshToken, error) {
	var t model.RefreshToken
	err := r.db.WithContext(ctx).Where("jti = ?", jti).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &t, err
}

func (r *refreshTokenRepo) ListActiveByUser(ctx context.Context, userID, clientID string) ([]model.RefreshToken, error) {
	var list []model.RefreshToken
	q := r.db.WithContext(ctx).Where("user_id = ? AND revoked_at IS NULL AND expire_at > ?", userID, time.Now())
	if clientID != "" {
		q = q.Where("client_id = ?", clientID)
	}
	err := q.Order("created_at desc").Find(&list).Error
	return list, err
}

func (r *refreshTokenRepo) Revoke(ctx context.Context, jti string, at time.Time) error {
	return r.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("jti = ?", jti).Update("revoked_at", at).Error
}

func (r *refreshTokenRepo) RevokeAllByUser(ctx context.Context, userID, clientID string, at time.Time) error {
	q := r.db.WithContext(ctx).Model(&model.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", userID)
	if clientID != "" {
		q = q.Where("client_id = ?", clientID)
	}
	return q.Update("revoked_at", at).Error
}

func (r *refreshTokenRepo) RevokeOthers(ctx context.Context, userID, clientID, keepJTI string, at time.Time) error {
	q := r.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL AND jti <> ?", userID, keepJTI)
	if clientID != "" {
		q = q.Where("client_id = ?", clientID)
	}
	return q.Update("revoked_at", at).Error
}

func (r *refreshTokenRepo) MarkReplaced(ctx context.Context, jti, newJTI string, at time.Time) error {
	return r.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("jti = ?", jti).
		Updates(map[string]interface{}{"revoked_at": at, "replaced_by_jti": newJTI}).Error
}

func (r *refreshTokenRepo) ConsumeActive(ctx context.Context, jti, newJTI string, at time.Time) (bool, error) {
	res := r.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("jti = ? AND revoked_at IS NULL", jti).
		Updates(map[string]interface{}{"revoked_at": at, "replaced_by_jti": newJTI})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

type oauthAccountRepo struct{ db *gorm.DB }

func NewOAuthAccountRepo(db *gorm.DB) OAuthAccountRepo { return &oauthAccountRepo{db: db} }

func (r *oauthAccountRepo) Upsert(ctx context.Context, acc *model.OAuthAccount) error {
	var existing model.OAuthAccount
	err := r.db.WithContext(ctx).Where("provider = ? AND subject = ?", acc.Provider, acc.Subject).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(acc).Error
	}
	if err != nil {
		return err
	}
	acc.ID = existing.ID
	acc.CreatedAt = existing.CreatedAt
	return r.db.WithContext(ctx).Save(acc).Error
}

func (r *oauthAccountRepo) Find(ctx context.Context, provider, subject string) (*model.OAuthAccount, error) {
	var acc model.OAuthAccount
	err := r.db.WithContext(ctx).Where("provider = ? AND subject = ?", provider, subject).First(&acc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &acc, err
}

type auditRepo struct{ db *gorm.DB }

func NewAuditRepo(db *gorm.DB) AuditRepo { return &auditRepo{db: db} }

func (r *auditRepo) Create(ctx context.Context, log *model.AuditLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

func (r *auditRepo) List(ctx context.Context, filter AuditFilter) ([]model.AuditLog, int64, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	q := r.db.WithContext(ctx).Model(&model.AuditLog{})
	if filter.TenantID != "" {
		q = q.Where("tenant_id = ?", filter.TenantID)
	}
	if filter.ClientID != "" {
		q = q.Where("client_id = ?", filter.ClientID)
	}
	if filter.UserID != "" {
		q = q.Where("user_id = ?", filter.UserID)
	}
	if filter.Action != "" {
		q = q.Where("action = ?", filter.Action)
	}
	if filter.Success != nil {
		q = q.Where("success = ?", *filter.Success)
	}
	if filter.From != nil {
		q = q.Where("created_at >= ?", *filter.From)
	}
	if filter.To != nil {
		q = q.Where("created_at <= ?", *filter.To)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.AuditLog
	err := q.Order("id desc").Limit(filter.Limit).Offset(filter.Offset).Find(&list).Error
	return list, total, err
}
