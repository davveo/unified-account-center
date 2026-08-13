package handler

import (
	"strconv"

	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/response"
	"github.com/davveo/unified-account-center/internal/repository"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/gin-gonic/gin"
)

type AdminHandler struct {
	admin *service.AdminService
}

func NewAdminHandler(admin *service.AdminService) *AdminHandler {
	return &AdminHandler{admin: admin}
}

func (h *AdminHandler) CreateApp(c *gin.Context) {
	var req service.CreateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.admin.CreateApp(c.Request.Context(), req)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) ListApps(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	list, total, err := h.admin.ListApps(c.Request.Context(), c.Query("tenant_id"), limit, offset)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list, "total": total})
}

func (h *AdminHandler) GetApp(c *gin.Context) {
	res, err := h.admin.GetApp(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) UpdateApp(c *gin.Context) {
	var req service.UpdateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.admin.UpdateApp(c.Request.Context(), c.Param("client_id"), req)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) RotateSecret(c *gin.Context) {
	res, err := h.admin.RotateSecret(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) RevealSecret(c *gin.Context) {
	secret, err := h.admin.RevealAppSecret(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"client_id": c.Param("client_id"), "client_secret": secret})
}

func (h *AdminHandler) ListChannels(c *gin.Context) {
	response.OK(c, gin.H{"channels": h.admin.ListChannels()})
}

func (h *AdminHandler) ListUsers(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	list, total, err := h.admin.ListUsers(c.Request.Context(), c.Query("tenant_id"), c.Query("q"), limit, offset)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list, "total": total})
}

func (h *AdminHandler) SetUserStatus(c *gin.Context) {
	var body struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.admin.SetUserStatus(c.Request.Context(), c.Param("user_id"), body.Status)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) ForceLogout(c *gin.Context) {
	var body struct {
		ClientID string `json:"client_id"`
	}
	_ = c.ShouldBindJSON(&body)
	if err := h.admin.ForceLogout(c.Request.Context(), c.Param("user_id"), body.ClientID); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) ListAudits(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	filter := repository.AuditFilter{
		TenantID: c.Query("tenant_id"),
		ClientID: c.Query("client_id"),
		UserID:   c.Query("user_id"),
		Action:   c.Query("action"),
		Limit:    limit,
		Offset:   offset,
	}
	if v := c.Query("success"); v == "true" || v == "false" {
		b := v == "true"
		filter.Success = &b
	}
	list, total, err := h.admin.ListAudits(c.Request.Context(), filter)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list, "total": total})
}

func (h *AdminHandler) ListOAuthProviders(c *gin.Context) {
	list, err := h.admin.ListOAuthProviders(c.Request.Context())
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list})
}

func (h *AdminHandler) UpsertOAuthProvider(c *gin.Context) {
	var req service.UpsertOAuthProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.admin.UpsertOAuthProvider(c.Request.Context(), req)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) ListUserSessions(c *gin.Context) {
	list, err := h.admin.ListUserSessions(c.Request.Context(), c.Param("user_id"), c.Query("client_id"))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list})
}

func (h *AdminHandler) MergeUsers(c *gin.Context) {
	var body struct {
		TargetUserID string `json:"target_user_id" binding:"required"`
		SourceUserID string `json:"source_user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	if err := h.admin.AdminMergeUsers(c.Request.Context(), body.TargetUserID, body.SourceUserID); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) ResetMFA(c *gin.Context) {
	if err := h.admin.AdminResetMFA(c.Request.Context(), c.Param("user_id")); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) UnlockRisk(c *gin.Context) {
	var body struct {
		Kind string `json:"kind" binding:"required"` // id | ip
		Key  string `json:"key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	if err := h.admin.AdminUnlock(c.Request.Context(), body.Kind, body.Key); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) CreateTenant(c *gin.Context) {
	var req service.CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.admin.CreateTenant(c.Request.Context(), req)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) ListTenants(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	list, total, err := h.admin.ListTenants(c.Request.Context(), limit, offset)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list, "total": total})
}

func (h *AdminHandler) GetTenant(c *gin.Context) {
	res, err := h.admin.GetTenant(c.Request.Context(), c.Param("tenant_id"))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) UpdateTenant(c *gin.Context) {
	var req service.UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.admin.UpdateTenant(c.Request.Context(), c.Param("tenant_id"), req)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) UpsertIdP(c *gin.Context) {
	var req service.UpsertIdPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.admin.UpsertEnterpriseIdP(c.Request.Context(), req)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) ListIdPs(c *gin.Context) {
	list, err := h.admin.ListEnterpriseIdPs(c.Request.Context(), c.Query("tenant_id"))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list})
}

func (h *AdminHandler) DeleteIdP(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if err := h.admin.DeleteEnterpriseIdP(c.Request.Context(), id); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) CreateInvite(c *gin.Context) {
	var req service.CreateInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	req.CreatedBy = c.GetHeader("X-Admin-Actor")
	res, err := h.admin.CreateInvite(c.Request.Context(), req)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) ListInvites(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	list, total, err := h.admin.ListInvites(c.Request.Context(), c.Query("tenant_id"), limit, offset)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list, "total": total})
}

func (h *AdminHandler) RevokeInvite(c *gin.Context) {
	if err := h.admin.RevokeInvite(c.Request.Context(), c.Param("code")); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) CreateUser(c *gin.Context) {
	var req service.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.admin.AdminCreateUser(c.Request.Context(), req)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AdminHandler) ListJoinRequests(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	list, total, err := h.admin.ListJoinRequests(c.Request.Context(), c.Query("tenant_id"), c.DefaultQuery("status", "pending"), limit, offset)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list, "total": total})
}

func (h *AdminHandler) ReviewJoin(c *gin.Context) {
	var body struct {
		Decision string `json:"decision" binding:"required"`
		Note     string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	if err := h.admin.ReviewJoinRequest(c.Request.Context(), c.Param("request_id"), body.Decision, c.GetHeader("X-Admin-Actor"), body.Note); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) AssignRole(c *gin.Context) {
	var req service.AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	if err := h.admin.AssignRole(c.Request.Context(), req); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) RevokeRole(c *gin.Context) {
	var body struct {
		UserID   string `json:"user_id" binding:"required"`
		TenantID string `json:"tenant_id"`
		Role     string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	if err := h.admin.RevokeRole(c.Request.Context(), body.UserID, body.TenantID, body.Role); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AdminHandler) ListRoles(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	list, total, err := h.admin.ListRoles(c.Request.Context(), c.Query("tenant_id"), limit, offset)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list, "total": total})
}
