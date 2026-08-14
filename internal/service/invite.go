package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/pkg/identity"
)

type CreateInviteRequest struct {
	TenantID  string `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	MaxUses   int    `json:"max_uses"`
	ExpireIn  int64  `json:"expire_in"` // seconds, 0=不过期
	Note      string `json:"note"`
	CreatedBy string `json:"-"`
}

type InviteView struct {
	Code      string `json:"code"`
	TenantID  string `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	MaxUses   int    `json:"max_uses"`
	UsedCount int    `json:"used_count"`
	ExpireAt  string `json:"expire_at,omitempty"`
	Status    string `json:"status"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
	InviteURL string `json:"invite_url,omitempty"`
}

func (s *AdminService) CreateInvite(ctx context.Context, req CreateInviteRequest) (*InviteView, error) {
	tid := strings.TrimSpace(req.TenantID)
	if tid == "" {
		tid = "default"
	}
	if _, err := s.GetTenant(ctx, tid); err != nil && tid != "default" {
		return nil, err
	}
	maxUses := req.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}
	var exp *time.Time
	if req.ExpireIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpireIn) * time.Second)
		exp = &t
	}
	inv := &model.Invite{
		Code: idgen.New("inv") + idgen.RandomHex(4),
		TenantID: tid, ClientID: strings.TrimSpace(req.ClientID),
		Email: strings.TrimSpace(req.Email), Phone: strings.TrimSpace(req.Phone),
		MaxUses: maxUses, ExpireAt: exp, CreatedBy: req.CreatedBy,
		Status: model.InviteStatusActive, Note: strings.TrimSpace(req.Note),
	}
	if err := s.repos.Invite.Create(ctx, inv); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "创建邀请失败", err)
	}
	v := toInviteView(inv)
	v.InviteURL = s.inviteMagicLink(inv)
	if inv.Email != "" && s.mailer != nil {
		_ = s.mailer.SendMail(ctx, inv.Email, "你收到一个注册邀请",
			"请点击链接完成注册：\n"+v.InviteURL+"\n\n邀请码："+inv.Code+"\n")
	}
	return &v, nil
}

func (s *AdminService) inviteMagicLink(inv *model.Invite) string {
	base := "http://127.0.0.1:8080"
	if s.cfg != nil && s.cfg.Server.PublicBaseURL != "" {
		base = strings.TrimRight(s.cfg.Server.PublicBaseURL, "/")
	}
	cid := inv.ClientID
	if cid == "" {
		cid = "app_demo"
	}
	return base + "/login?client_id=" + cid + "&invite_code=" + inv.Code + "&hint_email=" + inv.Email
}

func (s *AdminService) ListInvites(ctx context.Context, tenantID string, limit, offset int) ([]InviteView, int64, error) {
	list, total, err := s.repos.Invite.List(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, 0, errcode.Wrap(errcode.Internal, "查询邀请失败", err)
	}
	out := make([]InviteView, 0, len(list))
	for i := range list {
		v := toInviteView(&list[i])
		v.InviteURL = s.inviteMagicLink(&list[i])
		out = append(out, v)
	}
	return out, total, nil
}

func (s *AdminService) RevokeInvite(ctx context.Context, code string) error {
	inv, err := s.repos.Invite.FindByCode(ctx, code)
	if err != nil || inv == nil {
		return errcode.New(errcode.NotFound, "邀请不存在")
	}
	inv.Status = model.InviteStatusRevoked
	return s.repos.Invite.Update(ctx, inv)
}

func toInviteView(inv *model.Invite) InviteView {
	v := InviteView{
		Code: inv.Code, TenantID: inv.TenantID, ClientID: inv.ClientID,
		Email: inv.Email, Phone: inv.Phone, MaxUses: inv.MaxUses, UsedCount: inv.UsedCount,
		Status: inv.Status, Note: inv.Note, CreatedAt: inv.CreatedAt.Format("2006-01-02 15:04:05"),
	}
	if inv.ExpireAt != nil {
		v.ExpireAt = inv.ExpireAt.Format("2006-01-02 15:04:05")
	}
	return v
}

type CreateUserRequest struct {
	TenantID    string `json:"tenant_id"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Roles       []string `json:"roles"`
}

type CreateUserResult struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	DisplayName string   `json:"display_name"`
	Phone       string   `json:"phone,omitempty"`
	Email       string   `json:"email,omitempty"`
	TempPassword string  `json:"temp_password,omitempty"`
	Roles       []string `json:"roles"`
}

func (s *AdminService) AdminCreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResult, error) {
	tid := strings.TrimSpace(req.TenantID)
	if tid == "" {
		tid = "default"
	}
	phone := strings.TrimSpace(req.Phone)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if phone == "" && email == "" {
		return nil, errcode.New(errcode.BadRequest, "至少提供 phone 或 email")
	}
	userID := idgen.New("u")
	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		if phone != "" {
			display = identity.MaskPhone(phone)
		} else {
			display = identity.MaskEmail(email)
		}
	}
	user := &model.User{
		UserID: userID, TenantID: tid, DisplayName: display, Status: model.UserStatusActive,
	}
	if err := s.repos.User.Create(ctx, user); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "创建用户失败", err)
	}
	if phone != "" {
		norm, err := identity.NormalizePhone(phone)
		if err != nil {
			return nil, errcode.New(errcode.BadRequest, "手机号无效")
		}
		if err := s.repos.Identity.Create(ctx, &model.Identity{
			TenantID: tid, UserID: userID, Type: model.IdentityPhone, Provider: "", Identifier: norm, Verified: true,
		}); err != nil {
			return nil, errcode.Wrap(errcode.Internal, "绑定手机失败", err)
		}
		phone = norm
	}
	if email != "" {
		if err := s.repos.Identity.Create(ctx, &model.Identity{
			TenantID: tid, UserID: userID, Type: model.IdentityEmail, Provider: "", Identifier: email, Verified: true,
		}); err != nil {
			return nil, errcode.Wrap(errcode.Internal, "绑定邮箱失败", err)
		}
	}
	pwd := strings.TrimSpace(req.Password)
	temp := ""
	if pwd == "" {
		pwd = "Tmp" + idgen.RandomHex(6) + "!"
		temp = pwd
	}
	hash, err := crypto.HashPassword(pwd)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "哈希密码失败", err)
	}
	if err := s.repos.Credential.UpsertPassword(ctx, userID, hash); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "设置密码失败", err)
	}
	roles := req.Roles
	if len(roles) == 0 {
		roles = []string{model.RoleUser}
	}
	for _, role := range roles {
		_ = s.repos.Role.Upsert(ctx, &model.RoleBinding{UserID: userID, TenantID: tid, Role: role})
	}
	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		TenantID: tid, UserID: userID, Action: "admin_create_user", Success: true,
		Detail: "admin created user", CreatedAt: time.Now(),
	})
	return &CreateUserResult{
		UserID: userID, TenantID: tid, DisplayName: display,
		Phone: phone, Email: email, TempPassword: temp, Roles: roles,
	}, nil
}

type JoinRequestView struct {
	RequestID string `json:"request_id"`
	TenantID  string `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	Method    string `json:"method"`
	Identity  string `json:"identity"`
	Status    string `json:"status"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}

func (s *AdminService) ListJoinRequests(ctx context.Context, tenantID, status string, limit, offset int) ([]JoinRequestView, int64, error) {
	list, total, err := s.repos.Join.List(ctx, tenantID, status, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	out := make([]JoinRequestView, 0, len(list))
	for _, r := range list {
		out = append(out, JoinRequestView{
			RequestID: r.RequestID, TenantID: r.TenantID, ClientID: r.ClientID,
			Method: r.Method, Identity: r.Identity, Status: r.Status, Note: r.Note,
			CreatedAt: r.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return out, total, nil
}

func (s *AdminService) ReviewJoinRequest(ctx context.Context, requestID, decision, reviewer, note string) error {
	req, err := s.repos.Join.FindByRequestID(ctx, requestID)
	if err != nil || req == nil {
		return errcode.New(errcode.NotFound, "入驻申请不存在")
	}
	if req.Status != model.JoinPending {
		return errcode.New(errcode.BadRequest, "申请已处理")
	}
	decision = strings.ToLower(strings.TrimSpace(decision))
	if decision != "approve" && decision != "reject" {
		return errcode.New(errcode.BadRequest, "decision 仅支持 approve/reject")
	}
	if decision == "reject" {
		req.Status = model.JoinRejected
		req.Reviewer = reviewer
		req.Note = note
		return s.repos.Join.Update(ctx, req)
	}
	// approve → 创建用户
	userID := idgen.New("u")
	display := req.Identity
	var profile map[string]interface{}
	_ = json.Unmarshal([]byte(req.ProfileJSON), &profile)
	if profile != nil {
		if v, ok := profile["name"].(string); ok && v != "" {
			display = v
		}
	}
	user := &model.User{
		UserID: userID, TenantID: req.TenantID, DisplayName: display, Status: model.UserStatusActive,
	}
	if err := s.repos.User.Create(ctx, user); err != nil {
		return errcode.Wrap(errcode.Internal, "创建用户失败", err)
	}
	idType := req.IdType
	if idType == "" {
		idType = model.IdentityPhone
	}
	if err := s.repos.Identity.Create(ctx, &model.Identity{
		TenantID: req.TenantID, UserID: userID, Type: idType, Provider: req.Provider,
		Identifier: req.Identifier, Verified: true,
	}); err != nil {
		return errcode.Wrap(errcode.Internal, "创建身份失败", err)
	}
	_ = s.repos.Role.Upsert(ctx, &model.RoleBinding{UserID: userID, TenantID: req.TenantID, Role: model.RoleUser})
	req.Status = model.JoinApproved
	req.Reviewer = reviewer
	req.Note = note
	return s.repos.Join.Update(ctx, req)
}
