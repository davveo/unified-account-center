package service

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
)

func (s *AdminService) TestWebhook(ctx context.Context, id uint64, actor string) (map[string]interface{}, error) {
	if s.webhookBus == nil {
		return nil, errcode.New(errcode.Internal, "webhook 总线未启用")
	}
	deliveryID, err := s.webhookBus.TestEndpoint(ctx, id)
	if err != nil {
		return nil, errcode.Wrap(errcode.NotFound, "试投递失败", err)
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_webhook_test", Success: true,
		Detail: "endpoint=" + itoaU64(id), CreatedAt: time.Now(),
	})
	return map[string]interface{}{"delivery_id": deliveryID, "ok": true}, nil
}

func (s *AdminService) ReplayWebhookDelivery(ctx context.Context, id uint64, actor string) (map[string]interface{}, error) {
	if s.webhookBus == nil {
		return nil, errcode.New(errcode.Internal, "webhook 总线未启用")
	}
	deliveryID, err := s.webhookBus.ReplayDelivery(ctx, id)
	if err != nil {
		return nil, errcode.Wrap(errcode.NotFound, "重放失败", err)
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_webhook_replay", Success: true,
		Detail: "delivery=" + itoaU64(id), CreatedAt: time.Now(),
	})
	return map[string]interface{}{"delivery_id": deliveryID, "ok": true}, nil
}

type UserExport struct {
	User       UserAdminView             `json:"user"`
	Identities []map[string]interface{}  `json:"identities"`
	Roles      []model.RoleBinding       `json:"roles"`
	Sessions   []SessionView             `json:"sessions,omitempty"`
	Audits     []map[string]interface{}  `json:"recent_audits,omitempty"`
}

func (s *AdminService) ExportUser(ctx context.Context, userID string) (*UserExport, error) {
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	ids, _ := s.repos.Identity.ListByUserID(ctx, userID)
	idViews := make([]map[string]interface{}, 0, len(ids))
	for _, id := range ids {
		idViews = append(idViews, map[string]interface{}{
			"type": id.Type, "provider": id.Provider, "identifier": id.Identifier, "verified": id.Verified,
		})
	}
	roles, _ := s.repos.Role.ListByUser(ctx, userID)
	sessions, _ := s.ListUserSessions(ctx, userID, "")
	var audits []model.AuditLog
	_ = s.repos.DB.WithContext(ctx).Where("user_id = ?", userID).Order("id desc").Limit(50).Find(&audits)
	auditViews := make([]map[string]interface{}, 0, len(audits))
	for _, a := range audits {
		auditViews = append(auditViews, map[string]interface{}{
			"action": a.Action, "success": a.Success, "detail": a.Detail,
			"jti": a.JTI, "device_id": a.DeviceID, "created_at": a.CreatedAt.Format(time.RFC3339),
		})
	}
	return &UserExport{
		User: UserAdminView{
			UserID: user.UserID, TenantID: user.TenantID, DisplayName: user.DisplayName,
			Avatar: user.Avatar, Status: user.Status,
			CreatedAt: user.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt: user.UpdatedAt.Format("2006-01-02 15:04:05"),
		},
		Identities: idViews, Roles: roles, Sessions: sessions, Audits: auditViews,
	}, nil
}

func (s *AdminService) AnonymizeUser(ctx context.Context, userID, actor string) error {
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return errcode.New(errcode.NotFound, "用户不存在")
	}
	user.DisplayName = "已注销用户"
	user.Avatar = ""
	user.Status = model.UserStatusDisabled
	user.PrefNotifyEmail = false
	user.PrefNotifySMS = false
	if err := s.repos.User.Update(ctx, user); err != nil {
		return errcode.Wrap(errcode.Internal, "更新用户失败", err)
	}
	ids, _ := s.repos.Identity.ListByUserID(ctx, userID)
	for i := range ids {
		ids[i].Identifier = "anon_" + idgen.RandomHex(8)
		ids[i].Verified = false
		_ = s.repos.DB.WithContext(ctx).Save(&ids[i]).Error
	}
	_ = s.ForceLogout(ctx, userID, "")
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		TenantID: user.TenantID, UserID: actor, Action: "admin_user_anonymize", Success: true,
		Detail: userID, CreatedAt: time.Now(),
	})
	return nil
}

type ImportUsersRequest struct {
	TenantID string `json:"tenant_id"`
	CSV      string `json:"csv"` // header: phone,email,display_name,password,role
}

type ImportUsersResult struct {
	Created int      `json:"created"`
	Failed  int      `json:"failed"`
	Errors  []string `json:"errors,omitempty"`
	UserIDs []string `json:"user_ids,omitempty"`
}

func (s *AdminService) ImportUsers(ctx context.Context, req ImportUsersRequest, actor string) (*ImportUsersResult, error) {
	tid := strings.TrimSpace(req.TenantID)
	if tid == "" {
		tid = "default"
	}
	csvText := strings.TrimSpace(req.CSV)
	if csvText == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 csv")
	}
	r := csv.NewReader(strings.NewReader(csvText))
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil, errcode.New(errcode.BadRequest, "CSV 解析失败")
	}
	start := 0
	if len(rows[0]) > 0 && (strings.EqualFold(rows[0][0], "phone") || strings.EqualFold(rows[0][0], "email")) {
		start = 1
	}
	out := &ImportUsersResult{}
	for i := start; i < len(rows); i++ {
		row := rows[i]
		for len(row) < 5 {
			row = append(row, "")
		}
		phone, email, name, pwd, role := strings.TrimSpace(row[0]), strings.TrimSpace(row[1]), strings.TrimSpace(row[2]), strings.TrimSpace(row[3]), strings.TrimSpace(row[4])
		if phone == "" && email == "" {
			out.Failed++
			out.Errors = append(out.Errors, "row "+itoaU64(uint64(i+1))+": 缺少 phone/email")
			continue
		}
		var roles []string
		if role != "" {
			roles = []string{role}
		}
		res, err := s.AdminCreateUser(ctx, CreateUserRequest{
			TenantID: tid, Phone: phone, Email: email, DisplayName: name, Password: pwd, Roles: roles,
		})
		if err != nil {
			out.Failed++
			out.Errors = append(out.Errors, "row "+itoaU64(uint64(i+1))+": "+err.Error())
			continue
		}
		out.Created++
		out.UserIDs = append(out.UserIDs, res.UserID)
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		TenantID: tid, UserID: actor, Action: "admin_users_import", Success: true,
		Detail: mustJSON(map[string]interface{}{"created": out.Created, "failed": out.Failed}),
		CreatedAt: time.Now(),
	})
	return out, nil
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
