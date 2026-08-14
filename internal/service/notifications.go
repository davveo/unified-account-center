package service

import (
	"context"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
)

type NotificationView struct {
	ID        uint64 `json:"id"`
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Read      bool   `json:"read"`
	CreatedAt string `json:"created_at"`
}

func (s *AuthService) ListNotifications(ctx context.Context, userID string, limit int) ([]NotificationView, error) {
	if limit <= 0 {
		limit = 50
	}
	var list []model.UserNotification
	if err := s.repos.DB.WithContext(ctx).Where("user_id = ?", userID).
		Order("id desc").Limit(limit).Find(&list).Error; err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询通知失败", err)
	}
	out := make([]NotificationView, 0, len(list))
	for _, n := range list {
		out = append(out, NotificationView{
			ID: n.ID, Kind: n.Kind, Title: n.Title, Body: n.Body, Read: n.Read,
			CreatedAt: n.CreatedAt.Format(time.RFC3339),
		})
	}
	return out, nil
}

func (s *AuthService) MarkNotificationRead(ctx context.Context, userID string, id uint64) error {
	res := s.repos.DB.WithContext(ctx).Model(&model.UserNotification{}).
		Where("id = ? AND user_id = ?", id, userID).Update("read", true)
	if res.Error != nil {
		return errcode.Wrap(errcode.Internal, "更新通知失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return errcode.New(errcode.NotFound, "通知不存在")
	}
	return nil
}

type UserPreferencesView struct {
	NotifyLoginEmail       bool `json:"notify_login_email"`
	NotifyLoginSMS         bool `json:"notify_login_sms"`
	GlobalNotifyLoginEmail bool `json:"global_notify_login_email"`
	GlobalNotifyLoginSMS   bool `json:"global_notify_login_sms"`
}

type UpdatePreferencesDTO struct {
	NotifyLoginEmail *bool `json:"notify_login_email"`
	NotifyLoginSMS   *bool `json:"notify_login_sms"`
}

func (s *AuthService) GetPreferences(ctx context.Context, userID string) (*UserPreferencesView, error) {
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	out := &UserPreferencesView{
		NotifyLoginEmail: user.PrefNotifyEmail,
		NotifyLoginSMS:   user.PrefNotifySMS,
	}
	if s.cfg != nil {
		out.GlobalNotifyLoginEmail = s.cfg.Password.NotifyLoginEmail
		out.GlobalNotifyLoginSMS = s.cfg.Password.NotifyLoginSMS
	}
	return out, nil
}

func (s *AuthService) UpdatePreferences(ctx context.Context, userID string, dto UpdatePreferencesDTO) (*UserPreferencesView, error) {
	if dto.NotifyLoginEmail == nil && dto.NotifyLoginSMS == nil {
		return nil, errcode.New(errcode.BadRequest, "至少提供一个字段")
	}
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	if dto.NotifyLoginEmail != nil {
		user.PrefNotifyEmail = *dto.NotifyLoginEmail
	}
	if dto.NotifyLoginSMS != nil {
		user.PrefNotifySMS = *dto.NotifyLoginSMS
	}
	if err := s.repos.User.Update(ctx, user); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "更新偏好失败", err)
	}
	return s.GetPreferences(ctx, userID)
}
