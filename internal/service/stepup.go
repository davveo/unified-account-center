package service

import (
	"context"
	"time"

	"github.com/davveo/unified-account-center/internal/authenticator"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
)

const stepUpTTL = 5 * time.Minute

type StepUpDTO struct {
	Method     string            `json:"method" binding:"required"`
	Identity   string            `json:"identity"`
	Provider   string            `json:"provider"`
	Credential map[string]string `json:"credential"`
}

type StepUpResult struct {
	StepUpToken string `json:"step_up_token"`
	ExpireIn    int64  `json:"expire_in"`
}

func (s *AuthService) StepUp(ctx context.Context, meta RequestMeta, userID string, dto StepUpDTO) (*StepUpResult, error) {
	if dto.Method == model.MethodTOTP {
		code := ""
		if dto.Credential != nil {
			code = dto.Credential["code"]
			if code == "" {
				code = dto.Credential["otp"]
			}
		}
		return s.stepUpTOTP(ctx, meta, userID, code)
	}
	app, err := s.requireApp(ctx, meta.ClientID)
	if err != nil {
		return nil, err
	}
	auth, ok := s.auths.Get(dto.Method)
	if !ok {
		return nil, errcode.New(errcode.BadRequest, "不支持的验证方式")
	}
	if dto.Credential == nil {
		dto.Credential = map[string]string{}
	}
	principal, err := auth.Verify(ctx, authenticator.VerifyRequest{
		ClientID:   meta.ClientID,
		TenantID:   app.TenantID,
		Method:     dto.Method,
		Identity:   dto.Identity,
		Provider:   dto.Provider,
		Credential: dto.Credential,
		Scene:      model.SceneStepUp,
		IP:         meta.IP,
	})
	if err != nil {
		return nil, err
	}
	// 确认身份属于当前用户
	if uid, ok := principal.Profile["user_id"].(string); ok && uid != "" && uid != userID {
		return nil, errcode.New(errcode.InvalidCred, "二次验证身份不匹配")
	}
	if _, ok := principal.Profile["user_id"].(string); !ok {
		idn, err := s.repos.Identity.FindByUnique(ctx, app.TenantID, principal.Type, principal.Provider, principal.Identifier)
		if err != nil || idn == nil || idn.UserID != userID {
			return nil, errcode.New(errcode.InvalidCred, "二次验证身份不匹配")
		}
	}
	token := idgen.New("su") + idgen.RandomHex(8)
	if err := s.redis.SetJSON(ctx, stepUpKey(token), map[string]string{
		"user_id":   userID,
		"client_id": app.ClientID,
	}, stepUpTTL); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "签发二次验证凭证失败", err)
	}
	s.audit(ctx, app, userID, "step_up_ok", true, dto.Method, meta)
	return &StepUpResult{StepUpToken: token, ExpireIn: int64(stepUpTTL.Seconds())}, nil
}

func (s *AuthService) consumeStepUp(ctx context.Context, userID, clientID, token string) error {
	if token == "" {
		return errcode.New(errcode.BadRequest, "缺少 step_up_token，请先完成二次验证")
	}
	var payload map[string]string
	ok, err := s.redis.GetDelJSON(ctx, stepUpKey(token), &payload)
	if err != nil {
		return errcode.Wrap(errcode.Internal, "校验二次验证失败", err)
	}
	if !ok || payload["user_id"] != userID || payload["client_id"] != clientID {
		return errcode.New(errcode.InvalidCred, "二次验证凭证无效或已过期")
	}
	return nil
}

func stepUpKey(token string) string { return "uac:stepup:" + token }
