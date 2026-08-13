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
	list, total, err := h.admin.ListApps(c.Request.Context(), limit, offset)
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
