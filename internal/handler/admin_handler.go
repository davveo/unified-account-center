package handler

import (
	"strconv"

	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/response"
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

func (h *AdminHandler) ListChannels(c *gin.Context) {
	response.OK(c, gin.H{"channels": h.admin.ListChannels()})
}
