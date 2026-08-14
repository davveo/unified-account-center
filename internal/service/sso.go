package service

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
)

type UpsertIdPRequest struct {
	TenantID     string `json:"tenant_id" binding:"required"`
	Domain       string `json:"domain" binding:"required"`
	Provider     string `json:"provider" binding:"required"`
	Protocol     string `json:"protocol"` // oidc | saml
	JITEnabled   *bool  `json:"jit_enabled"`
	AttrMap      string `json:"attr_map"`
	SAMLEntityID string `json:"saml_entity_id"`
	SAMLSSOURL   string `json:"saml_sso_url"`
	SAMLCertPEM  string `json:"saml_cert_pem"`
	Enabled      *bool  `json:"enabled"`
}

type SSODiscoverResult struct {
	Domain     string `json:"domain"`
	Provider   string `json:"provider"`
	Protocol   string `json:"protocol"`
	TenantID   string `json:"tenant_id"`
	JITEnabled bool   `json:"jit_enabled"`
	ForceSSO   bool   `json:"force_sso"`
	SAMLStart  string `json:"saml_start_url,omitempty"`
}

func (s *AdminService) UpsertEnterpriseIdP(ctx context.Context, req UpsertIdPRequest) (*model.EnterpriseIdP, error) {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	domain = strings.TrimPrefix(domain, "@")
	if domain == "" || !strings.Contains(domain, ".") {
		return nil, errcode.New(errcode.BadRequest, "域名无效")
	}
	jit := true
	if req.JITEnabled != nil {
		jit = *req.JITEnabled
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	row := &model.EnterpriseIdP{
		TenantID:     strings.TrimSpace(req.TenantID),
		Domain:       domain,
		Provider:     strings.TrimSpace(req.Provider),
		Protocol:     strings.ToLower(strings.TrimSpace(req.Protocol)),
		JITEnabled:   jit,
		AttrMap:      strings.TrimSpace(req.AttrMap),
		SAMLEntityID: strings.TrimSpace(req.SAMLEntityID),
		SAMLSSOURL:   strings.TrimSpace(req.SAMLSSOURL),
		SAMLCertPEM:  strings.TrimSpace(req.SAMLCertPEM),
		Enabled:      enabled,
	}
	if row.Protocol == "" {
		if row.SAMLSSOURL != "" {
			row.Protocol = "saml"
		} else {
			row.Protocol = "oidc"
		}
	}
	if err := s.repos.IdP.Upsert(ctx, row); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "保存 IdP 失败", err)
	}
	// 同步租户 SSODomains
	if t, _ := s.repos.Tenant.FindByTenantID(ctx, row.TenantID); t != nil {
		found := false
		for _, d := range t.SSODomains {
			if d == domain {
				found = true
				break
			}
		}
		if !found {
			t.SSODomains = append(t.SSODomains, domain)
			_ = s.repos.Tenant.Update(ctx, t)
		}
	}
	return row, nil
}

func (s *AdminService) ListEnterpriseIdPs(ctx context.Context, tenantID string) ([]model.EnterpriseIdP, error) {
	return s.repos.IdP.ListByTenant(ctx, tenantID)
}

func (s *AdminService) DeleteEnterpriseIdP(ctx context.Context, id uint64) error {
	return s.repos.IdP.Delete(ctx, id)
}

func (s *AuthService) DiscoverSSO(ctx context.Context, clientID, email string) (*SSODiscoverResult, error) {
	app, err := s.requireApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return nil, errcode.New(errcode.BadRequest, "邮箱无效")
	}
	domain := email[at+1:]
	idp, err := s.repos.IdP.FindByDomain(ctx, domain)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询 IdP 失败", err)
	}
	if idp == nil {
		return nil, errcode.New(errcode.NotFound, "该域名未配置企业 SSO")
	}
	if idp.TenantID != "" && idp.TenantID != app.TenantID && app.TenantID != "default" {
		// 应用租户与 IdP 租户不一致时仍允许发现，但提示以 IdP 租户为准
	}
	tenant, _ := s.loadTenant(ctx, idp.TenantID)
	force := false
	if tenant != nil {
		force = tenant.ForceSSO
	}
	out := &SSODiscoverResult{
		Domain: domain, Provider: idp.Provider, Protocol: idp.Protocol, TenantID: idp.TenantID,
		JITEnabled: idp.JITEnabled, ForceSSO: force,
	}
	if out.Protocol == "" {
		if idp.SAMLSSOURL != "" {
			out.Protocol = "saml"
		} else {
			out.Protocol = "oidc"
		}
	}
	if out.Protocol == "saml" {
		out.SAMLStart = "/api/v1/auth/saml/start?domain=" + domain
	}
	return out, nil
}

func (s *AuthService) assertLocalLoginAllowed(ctx context.Context, app *model.App, method string) error {
	tenant, err := s.loadTenant(ctx, app.TenantID)
	if err != nil {
		return err
	}
	isPassword := method == model.MethodPhonePassword || method == model.MethodEmailPassword
	isOTP := method == model.MethodPhoneOTP || method == model.MethodEmailOTP
	if tenant.ForceSSO && (isPassword || isOTP) {
		return errcode.New(errcode.ForbiddenApp, "该租户强制企业 SSO，请使用企业邮箱登录")
	}
	if tenant.DisableLocalPassword && isPassword {
		return errcode.New(errcode.ForbiddenApp, "该租户已禁用本地密码登录")
	}
	return nil
}

// applyIdPJITAttrMap 按企业 IdP 属性映射补全 profile（email/name/avatar）。
func applyIdPJITAttrMap(profile map[string]interface{}, attrMapJSON string) {
	if profile == nil || attrMapJSON == "" {
		return
	}
	var m map[string]string
	if json.Unmarshal([]byte(attrMapJSON), &m) != nil {
		return
	}
	remap := func(std, key string) {
		if key == "" || key == std {
			return
		}
		if _, ok := profile[std]; ok {
			return
		}
		if v, ok := profile[key]; ok {
			profile[std] = v
		}
	}
	remap("email", m["email"])
	remap("name", m["name"])
	remap("avatar", m["avatar"])
}
