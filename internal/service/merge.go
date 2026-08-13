package service

import (
	"context"
	"fmt"
	"time"

	"github.com/davveo/unified-account-center/internal/authenticator"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/pkg/identity"
)

const mergeTokenTTL = 10 * time.Minute

type MergeStartDTO struct {
	Method     string            `json:"method" binding:"required"`
	Identity   string            `json:"identity" binding:"required"`
	Provider   string            `json:"provider"`
	Credential map[string]string `json:"credential"`
}

type MergeStartResult struct {
	MergeToken     string `json:"merge_token"`
	ExpireIn       int64  `json:"expire_in"`
	SourceUserID   string `json:"source_user_id"`
	SourceHint     string `json:"source_hint"`
}

type mergePayload struct {
	TargetUserID string `json:"target_user_id"`
	SourceUserID string `json:"source_user_id"`
	ClientID     string `json:"client_id"`
}

// MergeStart：当前用户验证「对方账户」的一种登录方式，签发合并令牌（将对方合并入当前用户）。
func (s *AuthService) MergeStart(ctx context.Context, meta RequestMeta, targetUserID string, dto MergeStartDTO) (*MergeStartResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	auth, ok := s.auths.Get(dto.Method)
	if !ok {
		return nil, errcode.New(errcode.BadRequest, "不支持的验证方式")
	}
	if dto.Credential == nil {
		dto.Credential = map[string]string{}
	}
	principal, err := auth.Verify(ctx, authenticator.VerifyRequest{
		ClientID: meta.ClientID, TenantID: app.TenantID, Method: dto.Method,
		Identity: dto.Identity, Provider: dto.Provider, Credential: dto.Credential,
		Scene: model.SceneMerge, IP: meta.IP,
	})
	if err != nil {
		return nil, err
	}
	idn, err := s.repos.Identity.FindByUnique(ctx, app.TenantID, principal.Type, principal.Provider, principal.Identifier)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询身份失败", err)
	}
	if idn == nil {
		return nil, errcode.New(errcode.NotFound, "对方身份不存在")
	}
	if idn.UserID == targetUserID {
		return nil, errcode.New(errcode.BadRequest, "该身份已属于当前用户，无需合并")
	}
	token := idgen.New("mg") + idgen.RandomHex(8)
	if err := s.redis.SetJSON(ctx, mergeKey(token), mergePayload{
		TargetUserID: targetUserID, SourceUserID: idn.UserID, ClientID: app.ClientID,
	}, mergeTokenTTL); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "签发合并令牌失败", err)
	}
	s.audit(ctx, app, targetUserID, "merge_start", true, idn.UserID, meta)
	hint := principal.Identifier
	if principal.Type == model.IdentityPhone {
		hint = identity.MaskPhone(principal.Identifier)
	} else if principal.Type == model.IdentityEmail {
		hint = identity.MaskEmail(principal.Identifier)
	}
	return &MergeStartResult{
		MergeToken: token, ExpireIn: int64(mergeTokenTTL.Seconds()),
		SourceUserID: idn.UserID, SourceHint: hint,
	}, nil
}

type MergeConfirmDTO struct {
	MergeToken string `json:"merge_token" binding:"required"`
}

func (s *AuthService) MergeConfirm(ctx context.Context, meta RequestMeta, targetUserID string, dto MergeConfirmDTO) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	var payload mergePayload
	ok, err := s.redis.GetDelJSON(ctx, mergeKey(dto.MergeToken), &payload)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "读取合并令牌失败", err)
	}
	if !ok || payload.TargetUserID != targetUserID || payload.ClientID != app.ClientID {
		return errcode.New(errcode.InvalidCred, "合并令牌无效或已过期")
	}
	if err := s.mergeUsers(ctx, app.TenantID, payload.TargetUserID, payload.SourceUserID); err != nil {
		return err
	}
	s.audit(ctx, app, targetUserID, "merge_ok", true, payload.SourceUserID, meta)
	return nil
}

func mergeKey(token string) string { return "uac:merge:" + token }

func (s *AuthService) mergeUsers(ctx context.Context, tenantID, targetUserID, sourceUserID string) error {
	if targetUserID == sourceUserID {
		return errcode.New(errcode.BadRequest, "不能合并同一用户")
	}
	target, err := s.repos.User.FindByUserID(ctx, targetUserID)
	if err != nil || target == nil {
		return errcode.New(errcode.NotFound, "目标用户不存在")
	}
	source, err := s.repos.User.FindByUserID(ctx, sourceUserID)
	if err != nil || source == nil {
		return errcode.New(errcode.NotFound, "源用户不存在")
	}
	tx := s.repos.DB.WithContext(ctx).Begin()
	if tx.Error != nil {
		return errcode.Wrap(errcode.Internal, "开启事务失败", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 迁移 identities（冲突则跳过该条 —— 理论上 source 独占）
	if err := tx.Model(&model.Identity{}).Where("user_id = ?", sourceUserID).Update("user_id", targetUserID).Error; err != nil {
		tx.Rollback()
		return errcode.Wrap(errcode.Internal, "迁移身份失败", err)
	}
	if err := tx.Model(&model.OAuthAccount{}).Where("user_id = ?", sourceUserID).Update("user_id", targetUserID).Error; err != nil {
		tx.Rollback()
		return errcode.Wrap(errcode.Internal, "迁移 OAuth 失败", err)
	}
	if err := tx.Model(&model.WebAuthnCredential{}).Where("user_id = ?", sourceUserID).Update("user_id", targetUserID).Error; err != nil {
		tx.Rollback()
		return errcode.Wrap(errcode.Internal, "迁移 Passkey 失败", err)
	}
	// 密码：目标无密码时继承源密码；MFA 优先保留目标
	var srcCred, tgtCred model.Credential
	_ = tx.Where("user_id = ?", sourceUserID).First(&srcCred).Error
	_ = tx.Where("user_id = ?", targetUserID).First(&tgtCred).Error
	if srcCred.ID != 0 {
		if tgtCred.ID == 0 {
			srcCred.UserID = targetUserID
			srcCred.ID = 0
			_ = tx.Create(&srcCred).Error
		} else if tgtCred.PasswordHash == "" && srcCred.PasswordHash != "" {
			tgtCred.PasswordHash = srcCred.PasswordHash
			tgtCred.PasswordUpdatedAt = srcCred.PasswordUpdatedAt
			_ = tx.Save(&tgtCred).Error
		}
		_ = tx.Where("user_id = ?", sourceUserID).Delete(&model.Credential{}).Error
	}
	now := time.Now()
	_ = tx.Model(&model.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", sourceUserID).Update("revoked_at", now).Error
	source.Status = model.UserStatusDisabled
	source.DisplayName = source.DisplayName + " (merged)"
	if err := tx.Save(source).Error; err != nil {
		tx.Rollback()
		return errcode.Wrap(errcode.Internal, "禁用源用户失败", err)
	}
	_ = tx.Create(&model.AuditLog{
		TenantID: tenantID, UserID: targetUserID, Action: "user_merged", Success: true,
		Detail: fmt.Sprintf("merged %s into %s", sourceUserID, targetUserID), CreatedAt: now,
	}).Error
	if err := tx.Commit().Error; err != nil {
		return errcode.Wrap(errcode.Internal, "提交合并失败", err)
	}
	return nil
}

// AdminMergeUsers 管理端强制合并 source → target。
func (s *AdminService) AdminMergeUsers(ctx context.Context, targetUserID, sourceUserID string) error {
	auth := &AuthService{cfg: s.cfg, repos: s.repos, redis: s.redis}
	target, err := s.repos.User.FindByUserID(ctx, targetUserID)
	if err != nil || target == nil {
		return errcode.New(errcode.NotFound, "目标用户不存在")
	}
	if err := auth.mergeUsers(ctx, target.TenantID, targetUserID, sourceUserID); err != nil {
		return err
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		TenantID: target.TenantID, UserID: targetUserID, Action: "admin_merge", Success: true,
		Detail: "merged " + sourceUserID + " into " + targetUserID, CreatedAt: time.Now(),
	})
	return nil
}

// AdminUnlock 解除账号/IP 风控锁定。
func (s *AdminService) AdminUnlock(ctx context.Context, kind, key string) error {
	if kind != "id" && kind != "ip" {
		return errcode.New(errcode.BadRequest, "kind 仅支持 id/ip")
	}
	if key == "" {
		return errcode.New(errcode.BadRequest, "缺少 key")
	}
	if s.redis == nil {
		return errcode.New(errcode.Internal, "redis 未初始化")
	}
	return s.redis.Del(ctx, riskLockKey(kind, key))
}

func (s *AdminService) AdminResetMFA(ctx context.Context, userID string) error {
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return errcode.New(errcode.NotFound, "用户不存在")
	}
	cred, err := s.repos.Credential.FindByUserID(ctx, userID)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "查询凭证失败", err)
	}
	if cred == nil {
		return nil
	}
	cred.MFAEnabled = false
	cred.MFASecret = ""
	cred.MFABackupHashes = nil
	if err := s.repos.Credential.Save(ctx, cred); err != nil {
		return errcode.Wrap(errcode.Internal, "重置 MFA 失败", err)
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		TenantID: user.TenantID, UserID: userID, Action: "admin_mfa_reset", Success: true,
		Detail: "admin reset mfa for " + userID, CreatedAt: time.Now(),
	})
	return nil
}
