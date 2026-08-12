package handler

import (
	"github.com/davveo/unified-account-center/internal/middleware"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/response"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	auth  *service.AuthService
	oauth *service.OAuthService
}

func NewAuthHandler(auth *service.AuthService, oauth *service.OAuthService) *AuthHandler {
	return &AuthHandler{auth: auth, oauth: oauth}
}

func (h *AuthHandler) meta(c *gin.Context) service.RequestMeta {
	clientID, _ := c.Get(middleware.CtxClientID)
	cid, _ := clientID.(string)
	if cid == "" {
		cid = c.GetHeader("X-Client-Id")
	}
	return service.RequestMeta{
		ClientID: cid,
		IP:       c.ClientIP(),
		UA:       c.Request.UserAgent(),
	}
}

func (h *AuthHandler) Methods(c *gin.Context) {
	methods, err := h.auth.ListMethods(c.Request.Context(), h.meta(c).ClientID)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"methods": methods})
}

func (h *AuthHandler) Challenge(c *gin.Context) {
	var dto service.ChallengeDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.auth.Challenge(c.Request.Context(), h.meta(c), dto)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var dto service.LoginDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.auth.Login(c.Request.Context(), h.meta(c), dto)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.auth.Refresh(c.Request.Context(), h.meta(c), body.RefreshToken)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
		AllDevices   bool   `json:"all_devices"`
	}
	_ = c.ShouldBindJSON(&body)
	userID, _ := c.Get(middleware.CtxUserID)
	jti, _ := c.Get(middleware.CtxAccessJTI)
	uid, _ := userID.(string)
	accessJTI, _ := jti.(string)
	err := h.auth.Logout(c.Request.Context(), h.meta(c), uid, accessJTI, body.RefreshToken, body.AllDevices, middleware.AccessTTLFromCtx(c))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	res, err := h.auth.Me(c.Request.Context(), uid)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) Bind(c *gin.Context) {
	var dto service.LoginDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	if err := h.auth.Bind(c.Request.Context(), h.meta(c), uid, dto); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) Unbind(c *gin.Context) {
	var dto service.UnbindDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	if err := h.auth.Unbind(c.Request.Context(), h.meta(c), uid, dto); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) SetPassword(c *gin.Context) {
	var dto service.SetPasswordDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	if err := h.auth.SetPassword(c.Request.Context(), h.meta(c), uid, dto); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) ResetStart(c *gin.Context) {
	var dto service.ResetStartDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.auth.ResetPasswordStart(c.Request.Context(), h.meta(c), dto)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) ResetConfirm(c *gin.Context) {
	var dto service.ResetConfirmDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	if err := h.auth.ResetPasswordConfirm(c.Request.Context(), h.meta(c), dto); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) Introspect(c *gin.Context) {
	token := ""
	if c.Request.Method == "GET" {
		hAuth := c.GetHeader("Authorization")
		if len(hAuth) > 7 {
			token = hAuth[7:]
		}
	} else {
		var body struct {
			Token string `json:"token"`
		}
		_ = c.ShouldBindJSON(&body)
		token = body.Token
		if token == "" {
			hAuth := c.GetHeader("Authorization")
			if len(hAuth) > 7 {
				token = hAuth[7:]
			}
		}
	}
	res, err := h.auth.Introspect(c.Request.Context(), token)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) OAuthStart(c *gin.Context) {
	provider := c.Param("provider")
	res, err := h.oauth.Start(
		c.Request.Context(),
		h.meta(c).ClientID,
		provider,
		c.Query("redirect_uri"),
		c.Query("state"),
		c.Query("code_challenge"),
	)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) OAuthCallback(c *gin.Context) {
	// 中台回调入口：将 code/state 回传给应用（托管模式简化实现）
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")
	response.OK(c, gin.H{
		"provider": provider,
		"code":     code,
		"state":    state,
		"hint":     "请使用 POST /api/v1/auth/login method=oauth2 完成登录",
	})
}

func (h *AuthHandler) Health(c *gin.Context) {
	response.OK(c, gin.H{"status": "up"})
}
