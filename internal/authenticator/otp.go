package authenticator

import (
	"context"
	"time"

	"github.com/davveo/unified-account-center/internal/adapter"
	"github.com/davveo/unified-account-center/internal/adapter/captcha"
	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/identity"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/repository"
)

type OTPAuth struct {
	method  string
	idType  string // phone | email
	otpCfg  config.OTPConfig
	chRepo  repository.ChallengeRepo
	redis   *redisx.Client
	sms     adapter.SMSSender
	email   adapter.EmailSender
	captcha captcha.Verifier
}

func NewPhoneOTP(otpCfg config.OTPConfig, chRepo repository.ChallengeRepo,
	redis *redisx.Client, sms adapter.SMSSender, captchaVerifier captcha.Verifier) *OTPAuth {
	if captchaVerifier == nil {
		captchaVerifier = captcha.Noop{}
	}
	return &OTPAuth{
		method:  model.MethodPhoneOTP,
		idType:  model.IdentityPhone,
		otpCfg:  otpCfg,
		chRepo:  chRepo,
		redis:   redis,
		sms:     sms,
		captcha: captchaVerifier,
	}
}

func NewEmailOTP(otpCfg config.OTPConfig, chRepo repository.ChallengeRepo,
	redis *redisx.Client, mail adapter.EmailSender, captchaVerifier captcha.Verifier) *OTPAuth {
	if captchaVerifier == nil {
		captchaVerifier = captcha.Noop{}
	}
	return &OTPAuth{
		method:  model.MethodEmailOTP,
		idType:  model.IdentityEmail,
		otpCfg:  otpCfg,
		chRepo:  chRepo,
		redis:   redis,
		email:   mail,
		captcha: captchaVerifier,
	}
}

func (a *OTPAuth) Method() string { return a.method }

func (a *OTPAuth) normalize(raw string) (string, string, error) {
	if a.idType == model.IdentityPhone {
		n, err := identity.NormalizePhone(raw)
		if err != nil {
			return "", "", errcode.New(errcode.BadRequest, "手机号格式错误")
		}
		return n, identity.MaskPhone(n), nil
	}
	n, err := identity.NormalizeEmail(raw)
	if err != nil {
		return "", "", errcode.New(errcode.BadRequest, "邮箱格式错误")
	}
	return n, identity.MaskEmail(n), nil
}

func (a *OTPAuth) Challenge(ctx context.Context, req ChallengeRequest) (*ChallengeResult, error) {
	norm, masked, err := a.normalize(req.Identity)
	if err != nil {
		return nil, err
	}
	if err := a.captcha.Verify(ctx, req.CaptchaToken, req.IP); err != nil {
		return nil, err
	}

	// identity + IP 小时限流
	ok, wait, err := a.redis.Allow(ctx, "uac:rl:otp:id:"+norm, 10, time.Hour)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "限流失败", err)
	}
	if !ok {
		_ = wait
		return nil, errcode.New(errcode.RateLimited, "发送过于频繁，请稍后重试")
	}
	if req.IP != "" {
		ok, wait, err = a.redis.Allow(ctx, "uac:rl:otp:ip:"+req.IP, 30, time.Hour)
		if err != nil {
			return nil, errcode.Wrap(errcode.Internal, "限流失败", err)
		}
		if !ok {
			_ = wait
			return nil, errcode.New(errcode.RateLimited, "发送过于频繁，请稍后重试")
		}
	}

	// 日额度熔断（防短信成本爆炸）
	dayID := time.Now().UTC().Format("20060102")
	idDaily := a.otpCfg.DailyLimitPerIdentity
	if idDaily <= 0 {
		idDaily = 20
	}
	ok, _, err = a.redis.Allow(ctx, "uac:rl:otp:day:id:"+dayID+":"+norm, idDaily, 24*time.Hour)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "限流失败", err)
	}
	if !ok {
		return nil, errcode.New(errcode.RateLimited, "今日发码次数已达上限")
	}
	if req.IP != "" {
		ipDaily := a.otpCfg.DailyLimitPerIP
		if ipDaily <= 0 {
			ipDaily = 50
		}
		ok, _, err = a.redis.Allow(ctx, "uac:rl:otp:day:ip:"+dayID+":"+req.IP, ipDaily, 24*time.Hour)
		if err != nil {
			return nil, errcode.Wrap(errcode.Internal, "限流失败", err)
		}
		if !ok {
			return nil, errcode.New(errcode.RateLimited, "今日该网络发码次数已达上限")
		}
	}

	if a.otpCfg.ResendInterval > 0 {
		resendKey := "uac:otp:resend:" + a.method + ":" + norm
		set, err := a.redis.SetNX(ctx, resendKey, time.Duration(a.otpCfg.ResendInterval)*time.Second)
		if err != nil {
			return nil, errcode.Wrap(errcode.Internal, "限流失败", err)
		}
		if !set {
			return nil, errcode.New(errcode.RateLimited, "请稍后再发送验证码")
		}
	}

	code := idgen.RandomDigits(a.otpCfg.Length)
	chID := idgen.New("ch")
	ch := &model.AuthChallenge{
		ChallengeID: chID,
		ClientID:    req.ClientID,
		TenantID:    req.TenantID,
		Method:      a.method,
		Scene:       req.Scene,
		Identity:    norm,
		CodeHash:    crypto.HashOTP(code),
		ExpireAt:    time.Now().Add(time.Duration(a.otpCfg.TTL) * time.Second),
	}
	if err := a.chRepo.Create(ctx, ch); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "创建挑战失败", err)
	}

	if a.idType == model.IdentityPhone {
		if err := a.sms.SendOTP(ctx, norm, code, req.Scene); err != nil {
			return nil, errcode.Wrap(errcode.Internal, "短信发送失败", err)
		}
	} else {
		if err := a.email.SendOTP(ctx, norm, code, req.Scene); err != nil {
			return nil, errcode.Wrap(errcode.Internal, "邮件发送失败", err)
		}
	}

	return &ChallengeResult{
		ChallengeID:  chID,
		ExpireIn:     a.otpCfg.TTL,
		ResendAfter:  a.otpCfg.ResendInterval,
		MaskedTarget: masked,
	}, nil
}

func (a *OTPAuth) Verify(ctx context.Context, req VerifyRequest) (*IdentityPrincipal, error) {
	norm, _, err := a.normalize(req.Identity)
	if err != nil {
		return nil, err
	}
	challengeID := req.Credential["challenge_id"]
	otp := req.Credential["otp"]
	if challengeID == "" || otp == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 challenge_id 或 otp")
	}

	ch, err := a.chRepo.FindByID(ctx, challengeID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询挑战失败", err)
	}
	if ch == nil {
		return nil, errcode.New(errcode.InvalidCred, "挑战不存在")
	}
	if ch.Method != a.method || ch.Identity != norm {
		return nil, errcode.New(errcode.InvalidCred, "挑战与身份不匹配")
	}
	if ch.ClientID != "" && req.ClientID != "" && ch.ClientID != req.ClientID {
		return nil, errcode.New(errcode.InvalidCred, "挑战与应用不匹配")
	}
	if req.Scene != "" && ch.Scene != "" && ch.Scene != req.Scene {
		return nil, errcode.New(errcode.InvalidCred, "挑战场景不匹配")
	}
	if ch.ConsumedAt != nil {
		return nil, errcode.New(errcode.InvalidCred, "验证码已使用")
	}
	if time.Now().After(ch.ExpireAt) {
		return nil, errcode.New(errcode.InvalidCred, "验证码已过期")
	}
	if ch.TryCount >= a.otpCfg.MaxTries {
		return nil, errcode.New(errcode.InvalidCred, "验证码尝试次数过多")
	}

	if crypto.HashOTP(otp) != ch.CodeHash {
		_ = a.chRepo.IncrementTry(ctx, challengeID)
		return nil, errcode.New(errcode.InvalidCred, "验证码错误")
	}

	now := time.Now()
	if err := a.chRepo.MarkConsumed(ctx, challengeID, now); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "消费挑战失败", err)
	}

	return &IdentityPrincipal{
		Type:       a.idType,
		Provider:   "",
		Identifier: norm,
		Verified:   true,
		Profile:    map[string]interface{}{},
	}, nil
}
