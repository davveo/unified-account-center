package service

import (
	"context"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/repository"
)

type TenantView struct {
	TenantID             string   `json:"tenant_id"`
	Name                 string   `json:"name"`
	Status               string   `json:"status"`
	MaxApps              int      `json:"max_apps"`
	DailyOTPLimit        int      `json:"daily_otp_limit"`
	ForceSSO             bool     `json:"force_sso"`
	DisableLocalPassword bool     `json:"disable_local_password"`
	SSODomains           []string `json:"sso_domains"`
	AppCount             int64    `json:"app_count"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
}

type CreateTenantRequest struct {
	TenantID             string   `json:"tenant_id"`
	Name                 string   `json:"name" binding:"required"`
	MaxApps              int      `json:"max_apps"`
	DailyOTPLimit        int      `json:"daily_otp_limit"`
	ForceSSO             bool     `json:"force_sso"`
	DisableLocalPassword bool     `json:"disable_local_password"`
	SSODomains           []string `json:"sso_domains"`
}

type UpdateTenantRequest struct {
	Name                 *string  `json:"name"`
	Status               *string  `json:"status"`
	MaxApps              *int     `json:"max_apps"`
	DailyOTPLimit        *int     `json:"daily_otp_limit"`
	ForceSSO             *bool    `json:"force_sso"`
	DisableLocalPassword *bool    `json:"disable_local_password"`
	SSODomains           []string `json:"sso_domains"`
}

func toTenantView(t *model.Tenant, appCount int64) TenantView {
	return TenantView{
		TenantID: t.TenantID, Name: t.Name, Status: t.Status,
		MaxApps: t.MaxApps, DailyOTPLimit: t.DailyOTPLimit,
		ForceSSO: t.ForceSSO, DisableLocalPassword: t.DisableLocalPassword,
		SSODomains: append([]string{}, t.SSODomains...),
		AppCount: appCount,
		CreatedAt: t.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt: t.UpdatedAt.Format("2006-01-02 15:04:05"),
	}
}

func (s *AdminService) CreateTenant(ctx context.Context, req CreateTenantRequest) (*TenantView, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errcode.New(errcode.BadRequest, "租户名称不能为空")
	}
	tid := strings.TrimSpace(req.TenantID)
	if tid == "" {
		tid = idgen.New("ten")
	}
	if existing, _ := s.repos.Tenant.FindByTenantID(ctx, tid); existing != nil {
		return nil, errcode.New(errcode.ConflictAccount, "tenant_id 已存在")
	}
	maxApps := req.MaxApps
	if maxApps <= 0 {
		maxApps = 20
	}
	otpLimit := req.DailyOTPLimit
	if otpLimit <= 0 {
		otpLimit = 5000
	}
	row := &model.Tenant{
		TenantID: tid, Name: name, Status: model.TenantStatusActive,
		MaxApps: maxApps, DailyOTPLimit: otpLimit,
		ForceSSO: req.ForceSSO, DisableLocalPassword: req.DisableLocalPassword,
		SSODomains: normalizeDomains(req.SSODomains),
	}
	if err := s.repos.Tenant.Create(ctx, row); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "创建租户失败", err)
	}
	v := toTenantView(row, 0)
	return &v, nil
}

func (s *AdminService) UpdateTenant(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantView, error) {
	row, err := s.repos.Tenant.FindByTenantID(ctx, tenantID)
	if err != nil || row == nil {
		return nil, errcode.New(errcode.NotFound, "租户不存在")
	}
	if req.Name != nil {
		row.Name = strings.TrimSpace(*req.Name)
	}
	if req.Status != nil {
		row.Status = strings.TrimSpace(*req.Status)
	}
	if req.MaxApps != nil {
		row.MaxApps = *req.MaxApps
	}
	if req.DailyOTPLimit != nil {
		row.DailyOTPLimit = *req.DailyOTPLimit
	}
	if req.ForceSSO != nil {
		row.ForceSSO = *req.ForceSSO
	}
	if req.DisableLocalPassword != nil {
		row.DisableLocalPassword = *req.DisableLocalPassword
	}
	if req.SSODomains != nil {
		row.SSODomains = normalizeDomains(req.SSODomains)
	}
	if err := s.repos.Tenant.Update(ctx, row); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "更新租户失败", err)
	}
	n, _ := repository.CountAppsByTenant(ctx, s.repos.DB, tenantID)
	v := toTenantView(row, n)
	return &v, nil
}

func (s *AdminService) ListTenants(ctx context.Context, limit, offset int) ([]TenantView, int64, error) {
	list, total, err := s.repos.Tenant.List(ctx, limit, offset)
	if err != nil {
		return nil, 0, errcode.Wrap(errcode.Internal, "查询租户失败", err)
	}
	out := make([]TenantView, 0, len(list))
	for i := range list {
		n, _ := repository.CountAppsByTenant(ctx, s.repos.DB, list[i].TenantID)
		out = append(out, toTenantView(&list[i], n))
	}
	return out, total, nil
}

func (s *AdminService) GetTenant(ctx context.Context, tenantID string) (*TenantView, error) {
	row, err := s.repos.Tenant.FindByTenantID(ctx, tenantID)
	if err != nil || row == nil {
		return nil, errcode.New(errcode.NotFound, "租户不存在")
	}
	n, _ := repository.CountAppsByTenant(ctx, s.repos.DB, tenantID)
	v := toTenantView(row, n)
	return &v, nil
}

func (s *AdminService) EnsureDefaultTenant(ctx context.Context) error {
	existing, err := s.repos.Tenant.FindByTenantID(ctx, "default")
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	return s.repos.Tenant.Create(ctx, &model.Tenant{
		TenantID: "default", Name: "Default", Status: model.TenantStatusActive,
		MaxApps: 100, DailyOTPLimit: 100000,
	})
}

func normalizeDomains(in []string) model.StringList {
	out := make(model.StringList, 0, len(in))
	seen := map[string]struct{}{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "@")
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func (s *AuthService) loadTenant(ctx context.Context, tenantID string) (*model.Tenant, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	t, err := s.repos.Tenant.FindByTenantID(ctx, tenantID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询租户失败", err)
	}
	if t == nil {
		// 兼容未迁移环境：隐式 default
		if tenantID == "default" {
			return &model.Tenant{
				TenantID: "default", Name: "Default", Status: model.TenantStatusActive,
				MaxApps: 100, DailyOTPLimit: 100000,
			}, nil
		}
		return nil, errcode.New(errcode.NotFound, "租户不存在")
	}
	if t.Status != model.TenantStatusActive {
		return nil, errcode.New(errcode.ForbiddenApp, "租户已停用")
	}
	return t, nil
}

func (s *AuthService) assertTenantOTPQuota(ctx context.Context, tenantID string) error {
	t, err := s.loadTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if t.DailyOTPLimit <= 0 {
		return nil
	}
	ok, _, err := s.redis.Allow(ctx, "uac:tenant:otp:"+tenantID+":"+time.Now().UTC().Format("20060102"), t.DailyOTPLimit, 24*time.Hour)
	if err != nil {
		return nil
	}
	if !ok {
		s.fireRiskAlert(ctx, "tenant_otp_limit", map[string]interface{}{"tenant_id": tenantID, "limit": t.DailyOTPLimit})
		return errcode.New(errcode.RateLimited, "租户日发码额度已用尽")
	}
	return nil
}

func (s *AdminService) assertTenantAppQuota(ctx context.Context, tenantID string) error {
	t, err := s.repos.Tenant.FindByTenantID(ctx, tenantID)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "查询租户失败", err)
	}
	if t == nil {
		if tenantID == "default" {
			return nil
		}
		return errcode.New(errcode.NotFound, "租户不存在")
	}
	if t.Status != model.TenantStatusActive {
		return errcode.New(errcode.ForbiddenApp, "租户已停用")
	}
	if t.MaxApps <= 0 {
		return nil
	}
	n, err := repository.CountAppsByTenant(ctx, s.repos.DB, tenantID)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "统计应用失败", err)
	}
	if int(n) >= t.MaxApps {
		return errcode.New(errcode.ForbiddenApp, "租户应用数已达上限")
	}
	return nil
}
