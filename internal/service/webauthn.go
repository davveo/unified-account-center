package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type waUser struct {
	id          []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.id }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
func (u *waUser) WebAuthnIcon() string                       { return "" }

func (s *AuthService) webAuthn() (*webauthn.WebAuthn, error) {
	cfg := &webauthn.Config{
		RPDisplayName: s.cfg.WebAuthn.RPDisplayName,
		RPID:          s.cfg.WebAuthn.RPID,
		RPOrigins:     s.cfg.WebAuthn.RPOrigins,
	}
	return webauthn.New(cfg)
}

func (s *AuthService) loadWAUser(ctx context.Context, userID string) (*waUser, error) {
	user, err := s.repos.User.FindByUserID(ctx, userID)
	if err != nil || user == nil {
		return nil, errcode.New(errcode.NotFound, "用户不存在")
	}
	list, err := s.repos.WebAuthn.ListByUserID(ctx, userID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询 Passkey 失败", err)
	}
	creds := make([]webauthn.Credential, 0, len(list))
	for _, c := range list {
		id, err := base64.RawURLEncoding.DecodeString(c.CredentialID)
		if err != nil {
			id, _ = base64.StdEncoding.DecodeString(c.CredentialID)
		}
		pub, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
		if err != nil {
			pub, _ = base64.StdEncoding.DecodeString(c.PublicKey)
		}
		creds = append(creds, webauthn.Credential{
			ID:        id,
			PublicKey: pub,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
				AAGUID:    []byte(c.AAGUID),
			},
		})
	}
	name := user.DisplayName
	if name == "" {
		name = userID
	}
	return &waUser{id: []byte(userID), name: userID, displayName: name, creds: creds}, nil
}

func (s *AuthService) PasskeyRegisterBegin(ctx context.Context, meta RequestMeta, userID string) (map[string]interface{}, error) {
	if _, err := s.requireApp(ctx, meta.ClientID); err != nil {
		return nil, err
	}
	wa, err := s.webAuthn()
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "WebAuthn 初始化失败", err)
	}
	user, err := s.loadWAUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	options, session, err := wa.BeginRegistration(user)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "创建注册挑战失败", err)
	}
	sid := idgen.New("wa") + idgen.RandomHex(8)
	if err := s.redis.SetJSON(ctx, waSessionKey(sid), session, 5*time.Minute); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "保存 WebAuthn 会话失败", err)
	}
	return map[string]interface{}{
		"session_id": sid,
		"options":    options,
	}, nil
}

func (s *AuthService) PasskeyRegisterFinish(ctx context.Context, meta RequestMeta, userID, sessionID, name string, body []byte) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	wa, err := s.webAuthn()
	if err != nil {
		return errcode.Wrap(errcode.Internal, "WebAuthn 初始化失败", err)
	}
	var session webauthn.SessionData
	ok, err := s.redis.GetDelJSON(ctx, waSessionKey(sessionID), &session)
	if err != nil || !ok {
		return errcode.New(errcode.InvalidCred, "WebAuthn 会话无效")
	}
	user, err := s.loadWAUser(ctx, userID)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return errcode.Wrap(errcode.BadRequest, "Passkey 响应无效", err)
	}
	cred, err := wa.CreateCredential(user, session, parsed)
	if err != nil {
		return errcode.Wrap(errcode.InvalidCred, "Passkey 注册失败", err)
	}
	row := &model.WebAuthnCredential{
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		UserID:       userID,
		Name:         name,
		PublicKey:    base64.RawURLEncoding.EncodeToString(cred.PublicKey),
		SignCount:    cred.Authenticator.SignCount,
		AAGUID:       string(cred.Authenticator.AAGUID),
	}
	if row.Name == "" {
		row.Name = "Passkey"
	}
	if err := s.repos.WebAuthn.Create(ctx, row); err != nil {
		return errcode.Wrap(errcode.Internal, "保存 Passkey 失败", err)
	}
	s.audit(ctx, app, userID, "passkey_register", true, row.CredentialID, meta)
	return nil
}

func (s *AuthService) PasskeyLoginBegin(ctx context.Context, meta RequestMeta, userID string) (map[string]interface{}, error) {
	if _, err := s.requireApp(ctx, meta.ClientID); err != nil {
		return nil, err
	}
	wa, err := s.webAuthn()
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "WebAuthn 初始化失败", err)
	}
	user, err := s.loadWAUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(user.creds) == 0 {
		return nil, errcode.New(errcode.BadRequest, "用户尚未注册 Passkey")
	}
	options, session, err := wa.BeginLogin(user)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "创建登录挑战失败", err)
	}
	sid := idgen.New("wa") + idgen.RandomHex(8)
	payload := map[string]interface{}{"session": session, "user_id": userID}
	if err := s.redis.SetJSON(ctx, waSessionKey(sid), payload, 5*time.Minute); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "保存 WebAuthn 会话失败", err)
	}
	return map[string]interface{}{"session_id": sid, "options": options}, nil
}

func (s *AuthService) PasskeyLoginFinish(ctx context.Context, meta RequestMeta, sessionID string, body []byte, client ClientInfo) (*LoginResult, error) {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	wa, err := s.webAuthn()
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "WebAuthn 初始化失败", err)
	}
	var payload struct {
		Session webauthn.SessionData `json:"session"`
		UserID  string               `json:"user_id"`
	}
	ok, err := s.redis.GetDelJSON(ctx, waSessionKey(sessionID), &payload)
	if err != nil || !ok {
		return nil, errcode.New(errcode.InvalidCred, "WebAuthn 会话无效")
	}
	user, err := s.loadWAUser(ctx, payload.UserID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, errcode.Wrap(errcode.BadRequest, "Passkey 响应无效", err)
	}
	cred, err := wa.ValidateLogin(user, payload.Session, parsed)
	if err != nil {
		s.noteLoginFailure(ctx, payload.UserID, meta.IP)
		return nil, errcode.Wrap(errcode.InvalidCred, "Passkey 验证失败", err)
	}
	// 更新计数
	cid := base64.RawURLEncoding.EncodeToString(cred.ID)
	if row, _ := s.repos.WebAuthn.FindByCredentialID(ctx, cid); row != nil {
		row.SignCount = cred.Authenticator.SignCount
		now := time.Now()
		row.LastUsedAt = &now
		_ = s.repos.WebAuthn.Update(ctx, row)
	}
	u, _ := s.repos.User.FindByUserID(ctx, payload.UserID)
	token, err := s.issueTokens(ctx, app, u, client, &meta)
	if err != nil {
		return nil, err
	}
	_ = s.rememberDevice(ctx, u.UserID, app.ClientID, client, meta)
	s.clearLoginFailures(ctx, u.UserID, meta.IP)
	views, _ := s.identityViews(ctx, u.UserID)
	roles, _ := s.rolesForUser(ctx, u.UserID, app.TenantID)
	s.audit(ctx, app, u.UserID, "login_ok", true, "passkey", meta)
	return &LoginResult{
		User: userViewOf(u, roles), Identities: views, Token: *token,
	}, nil
}

func (s *AuthService) ListPasskeys(ctx context.Context, userID string) ([]model.WebAuthnCredential, error) {
	list, err := s.repos.WebAuthn.ListByUserID(ctx, userID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询 Passkey 失败", err)
	}
	for i := range list {
		list[i].PublicKey = ""
		list[i].Attestation = ""
	}
	return list, nil
}

func (s *AuthService) DeletePasskey(ctx context.Context, meta RequestMeta, userID string, id uint64) error {
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return err
	}
	if err := s.repos.WebAuthn.Delete(ctx, id, userID); err != nil {
		return errcode.Wrap(errcode.Internal, "删除 Passkey 失败", err)
	}
	s.audit(ctx, app, userID, "passkey_delete", true, jsonNumber(id), meta)
	return nil
}

func waSessionKey(id string) string { return "uac:webauthn:" + id }

func jsonNumber(id uint64) string {
	b, _ := json.Marshal(id)
	return string(b)
}
