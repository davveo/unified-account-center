package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/pquerna/otp/totp"
)

const mfaPendingTTL = 5 * time.Minute

type MFASetupResult struct {
	Secret    string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

type MFAEnableResult struct {
	BackupCodes []string `json:"backup_codes"`
}

type MFAStatus struct {
	Enabled       bool `json:"enabled"`
	BackupLeft    int  `json:"backup_codes_left"`
	PasskeyCount  int  `json:"passkey_count"`
}

type mfaPendingPayload struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
	DeviceID string `json:"device_id"`
	FP       string `json:"fingerprint"`
	IsNew    bool   `json:"is_new_user"`
}

func (s *AuthService) MFAStatus(ctx context.Context, userID string) (*MFAStatus, error) {
	cred, err := s.repos.Credential.FindByUserID(ctx, userID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询凭证失败", err)
	}
	st := &MFAStatus{}
	if cred != nil {
		st.Enabled = cred.MFAEnabled && cred.MFASecret != ""
		st.BackupLeft = len(cred.MFABackupHashes)
	}
	if list, err := s.repos.WebAuthn.ListByUserID(ctx, userID); err == nil {
		st.PasskeyCount = len(list)
	}
	return st, nil
}

func (s *AuthService) MFASetup(ctx context.Context, meta RequestMeta, userID string) (*MFASetupResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.cfg.JWT.Issuer,
		AccountName: userID,
		SecretSize:  20,
	})
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "生成 TOTP 失败", err)
	}
	cred, err := s.repos.Credential.Ensure(ctx, userID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "准备凭证失败", err)
	}
	if cred.MFAEnabled {
		return nil, errcode.New(errcode.BadRequest, "MFA 已启用，请先关闭再重新绑定")
	}
	cred.MFASecret = key.Secret()
	cred.MFAEnabled = false
	if err := s.repos.Credential.Save(ctx, cred); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "保存 MFA 密钥失败", err)
	}
	s.audit(ctx, app, userID, "mfa_setup", true, "totp", meta)
	return &MFASetupResult{Secret: key.Secret(), OTPAuthURL: key.URL()}, nil
}

func (s *AuthService) MFAEnable(ctx context.Context, meta RequestMeta, userID, code string) (*MFAEnableResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	cred, err := s.repos.Credential.FindByUserID(ctx, userID)
	if err != nil || cred == nil || cred.MFASecret == "" {
		return nil, errcode.New(errcode.BadRequest, "请先调用 MFA setup")
	}
	if !totp.Validate(strings.TrimSpace(code), cred.MFASecret) {
		return nil, errcode.New(errcode.InvalidCred, "TOTP 验证码错误")
	}
	codes, hashes := generateBackupCodes(8)
	cred.MFAEnabled = true
	cred.MFABackupHashes = hashes
	if err := s.repos.Credential.Save(ctx, cred); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "启用 MFA 失败", err)
	}
	s.audit(ctx, app, userID, "mfa_enable", true, "totp", meta)
	return &MFAEnableResult{BackupCodes: codes}, nil
}

func (s *AuthService) MFADisable(ctx context.Context, meta RequestMeta, userID, stepUpToken string) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	if err := s.consumeStepUp(ctx, userID, app.ClientID, stepUpToken); err != nil {
		return err
	}
	cred, err := s.repos.Credential.FindByUserID(ctx, userID)
	if err != nil || cred == nil {
		return errcode.New(errcode.NotFound, "凭证不存在")
	}
	cred.MFAEnabled = false
	cred.MFASecret = ""
	cred.MFABackupHashes = nil
	if err := s.repos.Credential.Save(ctx, cred); err != nil {
		return errcode.Wrap(errcode.Internal, "关闭 MFA 失败", err)
	}
	s.audit(ctx, app, userID, "mfa_disable", true, "", meta)
	return nil
}

type MFACompleteDTO struct {
	MFAToken string     `json:"mfa_token" binding:"required"`
	Code     string     `json:"code" binding:"required"` // totp 或备份码
	Client   ClientInfo `json:"client"`
}

func (s *AuthService) MFAComplete(ctx context.Context, meta RequestMeta, dto MFACompleteDTO) (*LoginResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	var pending mfaPendingPayload
	ok, err := s.redis.GetDelJSON(ctx, mfaPendingKey(dto.MFAToken), &pending)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "读取 MFA 会话失败", err)
	}
	if !ok || pending.ClientID != app.ClientID {
		return nil, errcode.New(errcode.InvalidCred, "MFA 会话无效或已过期")
	}
	if err := s.verifyMFACode(ctx, pending.UserID, dto.Code); err != nil {
		s.audit(ctx, app, pending.UserID, "mfa_fail", false, "", meta)
		s.noteLoginFailure(ctx, pending.UserID, meta.IP)
		return nil, err
	}
	user, err := s.repos.User.FindByUserID(ctx, pending.UserID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	client := dto.Client
	if client.DeviceID == "" {
		client.DeviceID = pending.DeviceID
	}
	if client.Fingerprint == "" {
		client.Fingerprint = pending.FP
	}
	token, err := s.issueTokens(ctx, app, user, client, meta)
	if err != nil {
		return nil, err
	}
	_ = s.rememberDevice(ctx, user.UserID, app.ClientID, client, meta)
	s.clearLoginFailures(ctx, user.UserID, meta.IP)
	views, _ := s.identityViews(ctx, user.UserID)
	s.audit(ctx, app, user.UserID, "login_ok", true, "mfa", meta)
	return &LoginResult{
		User: UserView{UserID: user.UserID, DisplayName: user.DisplayName, Avatar: user.Avatar, Status: user.Status},
		Identities: views, Token: *token, IsNewUser: pending.IsNew,
	}, nil
}

func (s *AuthService) verifyMFACode(ctx context.Context, userID, code string) error {
	cred, err := s.repos.Credential.FindByUserID(ctx, userID)
	if err != nil || cred == nil || !cred.MFAEnabled || cred.MFASecret == "" {
		return errcode.New(errcode.BadRequest, "用户未启用 MFA")
	}
	code = strings.TrimSpace(code)
	if totp.Validate(code, cred.MFASecret) {
		return nil
	}
	// 备份码
	h := crypto.HashToken(code)
	left := make(model.StringList, 0, len(cred.MFABackupHashes))
	used := false
	for _, x := range cred.MFABackupHashes {
		if !used && x == h {
			used = true
			continue
		}
		left = append(left, x)
	}
	if !used {
		return errcode.New(errcode.InvalidCred, "MFA 验证码错误")
	}
	cred.MFABackupHashes = left
	_ = s.repos.Credential.Save(ctx, cred)
	return nil
}

func (s *AuthService) createMFAPending(ctx context.Context, app *model.App, user *model.User, client ClientInfo, isNew bool) (string, []string, error) {
	token := idgen.New("mfa") + idgen.RandomHex(8)
	payload := mfaPendingPayload{
		UserID: user.UserID, ClientID: app.ClientID,
		DeviceID: client.DeviceID, FP: client.Fingerprint, IsNew: isNew,
	}
	if err := s.redis.SetJSON(ctx, mfaPendingKey(token), payload, mfaPendingTTL); err != nil {
		return "", nil, errcode.Wrap(errcode.Internal, "创建 MFA 会话失败", err)
	}
	methods := []string{"totp"}
	cred, _ := s.repos.Credential.FindByUserID(ctx, user.UserID)
	if cred != nil && len(cred.MFABackupHashes) > 0 {
		methods = append(methods, "backup_code")
	}
	return token, methods, nil
}

func (s *AuthService) userHasMFA(ctx context.Context, userID string) bool {
	cred, err := s.repos.Credential.FindByUserID(ctx, userID)
	return err == nil && cred != nil && cred.MFAEnabled && cred.MFASecret != ""
}

func mfaPendingKey(token string) string { return "uac:mfa:pending:" + token }

func generateBackupCodes(n int) ([]string, model.StringList) {
	codes := make([]string, 0, n)
	hashes := make(model.StringList, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 5)
		_, _ = rand.Read(b)
		code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
		if len(code) > 10 {
			code = code[:10]
		}
		codes = append(codes, code)
		hashes = append(hashes, crypto.HashToken(code))
	}
	return codes, hashes
}

func (s *AuthService) stepUpTOTP(ctx context.Context, meta RequestMeta, userID string, code string) (*StepUpResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	if err := s.verifyMFACode(ctx, userID, code); err != nil {
		s.audit(ctx, app, userID, "step_up_fail", false, "totp", meta)
		return nil, err
	}
	token := idgen.New("su") + idgen.RandomHex(8)
	if err := s.redis.SetJSON(ctx, stepUpKey(token), map[string]string{
		"user_id": userID, "client_id": app.ClientID,
	}, stepUpTTL); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "签发二次验证凭证失败", err)
	}
	s.audit(ctx, app, userID, "step_up_ok", true, "totp", meta)
	return &StepUpResult{StepUpToken: token, ExpireIn: int64(stepUpTTL.Seconds())}, nil
}
