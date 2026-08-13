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

func (h *AuthHandler) StepUp(c *gin.Context) {
	var dto service.StepUpDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	res, err := h.auth.StepUp(c.Request.Context(), h.meta(c), uid, dto)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
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
	bindUserID := ""
	if uid, ok := c.Get(middleware.CtxUserID); ok {
		bindUserID, _ = uid.(string)
	}
	res, err := h.oauth.Start(
		c.Request.Context(),
		h.meta(c).ClientID,
		provider,
		c.Query("redirect_uri"),
		c.Query("state"),
		c.Query("code_challenge"),
		bindUserID,
	)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) OAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")
	response.OK(c, gin.H{
		"provider": provider,
		"code":     code,
		"state":    state,
		"hint":     "请使用 POST /api/v1/auth/login 或 /identities/bind method=oauth2 完成",
	})
}

func (h *AuthHandler) HostedConfig(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		clientID = c.GetHeader("X-Client-Id")
	}
	res, err := h.auth.HostedConfig(c.Request.Context(), clientID)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) IssueHostedCode(c *gin.Context) {
	var body struct {
		RedirectURI     string `json:"redirect_uri" binding:"required"`
		State           string `json:"state"`
		CodeChallenge   string `json:"code_challenge"`
		AccessToken     string `json:"access_token" binding:"required"`
		RefreshToken    string `json:"refresh_token" binding:"required"`
		ExpireIn        int64  `json:"expire_in"`
		RefreshExpireIn int64  `json:"refresh_expire_in"`
		DeviceID        string `json:"device_id"`
		RefreshJTI      string `json:"refresh_jti"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	tok := service.TokenDTO{
		AccessToken: body.AccessToken, TokenType: "Bearer",
		ExpireIn: body.ExpireIn, RefreshToken: body.RefreshToken,
		RefreshExpireIn: body.RefreshExpireIn, DeviceID: body.DeviceID, RefreshJTI: body.RefreshJTI,
	}
	res, err := h.auth.IssueHostedCode(c.Request.Context(), h.meta(c), uid, tok, body.DeviceID, service.IssueHostedCodeDTO{
		RedirectURI: body.RedirectURI, State: body.State, CodeChallenge: body.CodeChallenge,
	})
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) ExchangeToken(c *gin.Context) {
	var dto service.ExchangeTokenDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.auth.ExchangeToken(c.Request.Context(), h.meta(c), dto)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) ListSessions(c *gin.Context) {
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	keep := h.auth.ResolveRefreshJTI(c.Request.Context(), c.Query("refresh_token"))
	list, err := h.auth.ListSessions(c.Request.Context(), h.meta(c), uid, keep)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list})
}

func (h *AuthHandler) RevokeSession(c *gin.Context) {
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	if err := h.auth.RevokeSession(c.Request.Context(), h.meta(c), uid, c.Param("jti")); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) RevokeOtherSessions(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
		KeepJTI      string `json:"keep_jti"`
	}
	_ = c.ShouldBindJSON(&body)
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	keep := body.KeepJTI
	if keep == "" {
		keep = h.auth.ResolveRefreshJTI(c.Request.Context(), body.RefreshToken)
	}
	if err := h.auth.RevokeOtherSessions(c.Request.Context(), h.meta(c), uid, keep); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) Health(c *gin.Context) {
	response.OK(c, gin.H{"status": "up"})
}
