package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"gorm.io/gorm"
)

type TenantRepo interface {
	Create(ctx context.Context, t *model.Tenant) error
	Update(ctx context.Context, t *model.Tenant) error
	FindByTenantID(ctx context.Context, tenantID string) (*model.Tenant, error)
	List(ctx context.Context, limit, offset int) ([]model.Tenant, int64, error)
}

type EnterpriseIdPRepo interface {
	Upsert(ctx context.Context, row *model.EnterpriseIdP) error
	FindByDomain(ctx context.Context, domain string) (*model.EnterpriseIdP, error)
	ListByTenant(ctx context.Context, tenantID string) ([]model.EnterpriseIdP, error)
	Delete(ctx context.Context, id uint64) error
}

type InviteRepo interface {
	Create(ctx context.Context, inv *model.Invite) error
	FindByCode(ctx context.Context, code string) (*model.Invite, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]model.Invite, int64, error)
	Update(ctx context.Context, inv *model.Invite) error
	Consume(ctx context.Context, code string) (bool, error)
}

type JoinRequestRepo interface {
	Create(ctx context.Context, req *model.JoinRequest) error
	FindByRequestID(ctx context.Context, requestID string) (*model.JoinRequest, error)
	List(ctx context.Context, tenantID, status string, limit, offset int) ([]model.JoinRequest, int64, error)
	Update(ctx context.Context, req *model.JoinRequest) error
}

type RoleRepo interface {
	Upsert(ctx context.Context, b *model.RoleBinding) error
	Delete(ctx context.Context, userID, tenantID, role string) error
	ListByUser(ctx context.Context, userID string) ([]model.RoleBinding, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]model.RoleBinding, int64, error)
}

type tenantRepo struct{ db *gorm.DB }

func NewTenantRepo(db *gorm.DB) TenantRepo { return &tenantRepo{db: db} }

func (r *tenantRepo) Create(ctx context.Context, t *model.Tenant) error {
	return r.db.WithContext(ctx).Create(t).Error
}
func (r *tenantRepo) Update(ctx context.Context, t *model.Tenant) error {
	return r.db.WithContext(ctx).Save(t).Error
}
func (r *tenantRepo) FindByTenantID(ctx context.Context, tenantID string) (*model.Tenant, error) {
	var t model.Tenant
	err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &t, err
}
func (r *tenantRepo) List(ctx context.Context, limit, offset int) ([]model.Tenant, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	var total int64
	if err := r.db.WithContext(ctx).Model(&model.Tenant{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.Tenant
	err := r.db.WithContext(ctx).Order("id desc").Limit(limit).Offset(offset).Find(&list).Error
	return list, total, err
}

type idpRepo struct{ db *gorm.DB }

func NewEnterpriseIdPRepo(db *gorm.DB) EnterpriseIdPRepo { return &idpRepo{db: db} }

func (r *idpRepo) Upsert(ctx context.Context, row *model.EnterpriseIdP) error {
	var existing model.EnterpriseIdP
	err := r.db.WithContext(ctx).Where("tenant_id = ? AND domain = ?", row.TenantID, row.Domain).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(row).Error
	}
	if err != nil {
		return err
	}
	row.ID = existing.ID
	row.CreatedAt = existing.CreatedAt
	return r.db.WithContext(ctx).Save(row).Error
}
func (r *idpRepo) FindByDomain(ctx context.Context, domain string) (*model.EnterpriseIdP, error) {
	var row model.EnterpriseIdP
	err := r.db.WithContext(ctx).Where("domain = ? AND enabled = ?", strings.ToLower(domain), true).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &row, err
}
func (r *idpRepo) ListByTenant(ctx context.Context, tenantID string) ([]model.EnterpriseIdP, error) {
	q := r.db.WithContext(ctx).Model(&model.EnterpriseIdP{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	var list []model.EnterpriseIdP
	err := q.Order("id desc").Find(&list).Error
	return list, err
}
func (r *idpRepo) Delete(ctx context.Context, id uint64) error {
	return r.db.WithContext(ctx).Delete(&model.EnterpriseIdP{}, id).Error
}

type inviteRepo struct{ db *gorm.DB }

func NewInviteRepo(db *gorm.DB) InviteRepo { return &inviteRepo{db: db} }

func (r *inviteRepo) Create(ctx context.Context, inv *model.Invite) error {
	return r.db.WithContext(ctx).Create(inv).Error
}
func (r *inviteRepo) FindByCode(ctx context.Context, code string) (*model.Invite, error) {
	var inv model.Invite
	err := r.db.WithContext(ctx).Where("code = ?", code).First(&inv).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &inv, err
}
func (r *inviteRepo) List(ctx context.Context, tenantID string, limit, offset int) ([]model.Invite, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	q := r.db.WithContext(ctx).Model(&model.Invite{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.Invite
	err := q.Order("id desc").Limit(limit).Offset(offset).Find(&list).Error
	return list, total, err
}
func (r *inviteRepo) Update(ctx context.Context, inv *model.Invite) error {
	return r.db.WithContext(ctx).Save(inv).Error
}
func (r *inviteRepo) Consume(ctx context.Context, code string) (bool, error) {
	now := time.Now()
	res := r.db.WithContext(ctx).Model(&model.Invite{}).
		Where("code = ? AND status = ? AND used_count < max_uses AND (expire_at IS NULL OR expire_at > ?)",
			code, model.InviteStatusActive, now).
		UpdateColumn("used_count", gorm.Expr("used_count + 1"))
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

type joinRepo struct{ db *gorm.DB }

func NewJoinRequestRepo(db *gorm.DB) JoinRequestRepo { return &joinRepo{db: db} }

func (r *joinRepo) Create(ctx context.Context, req *model.JoinRequest) error {
	return r.db.WithContext(ctx).Create(req).Error
}
func (r *joinRepo) FindByRequestID(ctx context.Context, requestID string) (*model.JoinRequest, error) {
	var req model.JoinRequest
	err := r.db.WithContext(ctx).Where("request_id = ?", requestID).First(&req).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &req, err
}
func (r *joinRepo) List(ctx context.Context, tenantID, status string, limit, offset int) ([]model.JoinRequest, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	q := r.db.WithContext(ctx).Model(&model.JoinRequest{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.JoinRequest
	err := q.Order("id desc").Limit(limit).Offset(offset).Find(&list).Error
	return list, total, err
}
func (r *joinRepo) Update(ctx context.Context, req *model.JoinRequest) error {
	return r.db.WithContext(ctx).Save(req).Error
}

type roleRepo struct{ db *gorm.DB }

func NewRoleRepo(db *gorm.DB) RoleRepo { return &roleRepo{db: db} }

func (r *roleRepo) Upsert(ctx context.Context, b *model.RoleBinding) error {
	var existing model.RoleBinding
	err := r.db.WithContext(ctx).Where("user_id = ? AND tenant_id = ? AND role = ?", b.UserID, b.TenantID, b.Role).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(b).Error
	}
	return err
}
func (r *roleRepo) Delete(ctx context.Context, userID, tenantID, role string) error {
	return r.db.WithContext(ctx).Where("user_id = ? AND tenant_id = ? AND role = ?", userID, tenantID, role).
		Delete(&model.RoleBinding{}).Error
}
func (r *roleRepo) ListByUser(ctx context.Context, userID string) ([]model.RoleBinding, error) {
	var list []model.RoleBinding
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&list).Error
	return list, err
}
func (r *roleRepo) List(ctx context.Context, tenantID string, limit, offset int) ([]model.RoleBinding, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	q := r.db.WithContext(ctx).Model(&model.RoleBinding{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.RoleBinding
	err := q.Order("id desc").Limit(limit).Offset(offset).Find(&list).Error
	return list, total, err
}

func CountAppsByTenant(ctx context.Context, db *gorm.DB, tenantID string) (int64, error) {
	var n int64
	err := db.WithContext(ctx).Model(&model.App{}).Where("tenant_id = ?", tenantID).Count(&n).Error
	return n, err
}
