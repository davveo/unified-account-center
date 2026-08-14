package handler

import (
	"strconv"

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
		ClientID:  cid,
		IP:        c.ClientIP(),
		UA:        c.Request.UserAgent(),
		RequestID: c.GetString("request_id"),
		DeviceID:  c.GetHeader("X-Device-Id"),
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

func (h *AuthHandler) UserInfo(c *gin.Context) {
	userID, _ := c.Get(middleware.CtxUserID)
	uid, _ := userID.(string)
	res, err := h.auth.UserInfo(c.Request.Context(), uid)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	// OIDC userinfo 直接返回 claims（非业务 envelope）
	c.JSON(200, res)
}

func (h *AuthHandler) OpenIDConfiguration(c *gin.Context) {
	base := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Host
	if base == "" {
		if c.Request.TLS != nil {
			base = "https"
		} else {
			base = "http"
		}
	}
	if xfHost := c.Request.Header.Get("X-Forwarded-Host"); xfHost != "" {
		host = xfHost
	}
	c.JSON(200, h.auth.OpenIDConfiguration(base+"://"+host))
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

func (h *AuthHandler) MFAStatus(c *gin.Context) {
	uid, _ := c.Get(middleware.CtxUserID)
	res, err := h.auth.MFAStatus(c.Request.Context(), uid.(string))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) MFASetup(c *gin.Context) {
	uid, _ := c.Get(middleware.CtxUserID)
	res, err := h.auth.MFASetup(c.Request.Context(), h.meta(c), uid.(string))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) MFAEnable(c *gin.Context) {
	var body struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	uid, _ := c.Get(middleware.CtxUserID)
	res, err := h.auth.MFAEnable(c.Request.Context(), h.meta(c), uid.(string), body.Code)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) MFADisable(c *gin.Context) {
	var body struct {
		StepUpToken string `json:"step_up_token"`
	}
	_ = c.ShouldBindJSON(&body)
	uid, _ := c.Get(middleware.CtxUserID)
	if err := h.auth.MFADisable(c.Request.Context(), h.meta(c), uid.(string), body.StepUpToken); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) MFAComplete(c *gin.Context) {
	var dto service.MFACompleteDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.auth.MFAComplete(c.Request.Context(), h.meta(c), dto)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) PasskeyRegisterBegin(c *gin.Context) {
	uid, _ := c.Get(middleware.CtxUserID)
	res, err := h.auth.PasskeyRegisterBegin(c.Request.Context(), h.meta(c), uid.(string))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) PasskeyRegisterFinish(c *gin.Context) {
	uid, _ := c.Get(middleware.CtxUserID)
	sessionID := c.Query("session_id")
	if sessionID == "" {
		sessionID = c.GetHeader("X-WebAuthn-Session")
	}
	name := c.Query("name")
	body, _ := c.GetRawData()
	if err := h.auth.PasskeyRegisterFinish(c.Request.Context(), h.meta(c), uid.(string), sessionID, name, body); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) PasskeyLoginBegin(c *gin.Context) {
	var body struct {
		UserID string `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	res, err := h.auth.PasskeyLoginBegin(c.Request.Context(), h.meta(c), body.UserID)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) PasskeyLoginFinish(c *gin.Context) {
	sessionID := c.Query("session_id")
	if sessionID == "" {
		sessionID = c.GetHeader("X-WebAuthn-Session")
	}
	var client service.ClientInfo
	_ = c.ShouldBindHeader(&client) // ignore
	client.DeviceID = c.GetHeader("X-Device-Id")
	client.Fingerprint = c.GetHeader("X-Device-Fingerprint")
	body, _ := c.GetRawData()
	res, err := h.auth.PasskeyLoginFinish(c.Request.Context(), h.meta(c), sessionID, body, client)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) ListPasskeys(c *gin.Context) {
	uid, _ := c.Get(middleware.CtxUserID)
	list, err := h.auth.ListPasskeys(c.Request.Context(), uid.(string))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"items": list})
}

func (h *AuthHandler) DeletePasskey(c *gin.Context) {
	uid, _ := c.Get(middleware.CtxUserID)
	id64, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if err := h.auth.DeletePasskey(c.Request.Context(), h.meta(c), uid.(string), id64); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) MergeStart(c *gin.Context) {
	var dto service.MergeStartDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	uid, _ := c.Get(middleware.CtxUserID)
	res, err := h.auth.MergeStart(c.Request.Context(), h.meta(c), uid.(string), dto)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) MergeConfirm(c *gin.Context) {
	var dto service.MergeConfirmDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		response.Fail(c, errcode.BadRequest, "参数错误")
		return
	}
	uid, _ := c.Get(middleware.CtxUserID)
	if err := h.auth.MergeConfirm(c.Request.Context(), h.meta(c), uid.(string), dto); err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) DiscoverSSO(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		var body struct {
			Email string `json:"email"`
		}
		_ = c.ShouldBindJSON(&body)
		email = body.Email
	}
	res, err := h.auth.DiscoverSSO(c.Request.Context(), h.meta(c).ClientID, email)
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) SAMLStart(c *gin.Context) {
	res, err := h.auth.StartSAML(c.Request.Context(), h.meta(c).ClientID, c.Query("domain"), c.Query("relay_state"))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	if c.Query("redirect") == "1" {
		c.Redirect(302, res.RedirectURL)
		return
	}
	response.OK(c, res)
}

func (h *AuthHandler) SAMLACS(c *gin.Context) {
	samlResp := c.PostForm("SAMLResponse")
	if samlResp == "" {
		var body struct {
			SAMLResponse string `json:"SAMLResponse"`
			RelayState   string `json:"RelayState"`
		}
		_ = c.ShouldBindJSON(&body)
		samlResp = body.SAMLResponse
		if c.PostForm("RelayState") == "" && body.RelayState != "" {
			c.Request.PostForm = map[string][]string{"RelayState": {body.RelayState}}
		}
	}
	res, err := h.auth.FinishSAML(c.Request.Context(), h.meta(c), samlResp, c.PostForm("RelayState"))
	if err != nil {
		response.FailErr(c, err)
		return
	}
	response.OK(c, res)
}
