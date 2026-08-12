package service_test

import (
	"context"
	"sync"
	"testing"

	"github.com/davveo/unified-account-center/internal/adapter/captcha"
	"github.com/davveo/unified-account-center/internal/authenticator"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/davveo/unified-account-center/internal/service"
)

func TestConcurrentRefreshOnlyOneWins(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13000130000"})
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13000130000",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613000130000")},
	})
	if err != nil {
		t.Fatal(err)
	}
	rt := login.Token.RefreshToken
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := env.auth.Refresh(ctx, meta(), rt)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok, fail := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else {
			fail++
		}
	}
	if ok != 1 {
		t.Fatalf("expect exactly 1 successful refresh, got ok=%d fail=%d", ok, fail)
	}
}

func TestStepUpRequiredForSetPassword(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "12900129000"})
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "12900129000",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8612900129000")},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = env.auth.SetPassword(ctx, meta(), login.User.UserID, service.SetPasswordDTO{Password: "Passw0rd1"})
	if !errcode.Is(err, errcode.BadRequest) && !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect step-up required, got %v", err)
	}
}

func TestRefreshReuseRevokesFamily(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13100131000"})
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13100131000",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613100131000")},
	})
	if err != nil {
		t.Fatal(err)
	}
	oldRT := login.Token.RefreshToken
	next, err := env.auth.Refresh(ctx, meta(), oldRT)
	if err != nil {
		t.Fatal(err)
	}
	// 复用已轮换的旧 refresh → 吊销家族
	_, err = env.auth.Refresh(ctx, meta(), oldRT)
	if err == nil {
		t.Fatal("expect reuse rejected")
	}
	_, err = env.auth.Refresh(ctx, meta(), next.RefreshToken)
	if err == nil {
		t.Fatal("expect family revoked after reuse")
	}
}

func TestCaptchaRequiredWhenEnabled(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	env.cfg.Captcha.Enabled = true
	repos := env.repos
	rdb := env.redis
	smsCap := env.sms
	emailCap := env.email
	cfg := env.cfg
	auths := authenticator.NewRegistry(
		authenticator.NewPhoneOTP(cfg.OTP, repos.Challenge, rdb, smsCap, captcha.NewMock(true)),
		authenticator.NewEmailOTP(cfg.OTP, repos.Challenge, rdb, emailCap, captcha.NewMock(true)),
		authenticator.NewPhonePassword(repos.Identity, repos.Credential, rdb),
		authenticator.NewEmailPassword(repos.Identity, repos.Credential, rdb),
	)
	authSvc := service.NewAuthService(cfg, repos, auths, jwtutil.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), rdb)

	_, err := authSvc.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13200132000"})
	if err == nil {
		t.Fatal("expect captcha required")
	}
	_, err = authSvc.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13200132000", CaptchaToken: "fail",
	})
	if err == nil {
		t.Fatal("expect captcha fail rejected")
	}
	_, err = authSvc.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13200132000", CaptchaToken: "ok-token",
	})
	if err != nil {
		t.Fatalf("expect captcha pass, got %v", err)
	}
}
