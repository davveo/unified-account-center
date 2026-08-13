package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/pquerna/otp/totp"
)

func TestMFASetupEnableAndLogin(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()

	ch, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139001"})
	if err != nil {
		t.Fatal(err)
	}
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139001",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613900139001")},
		Client:     service.ClientInfo{DeviceID: "dev-a"},
	})
	if err != nil {
		t.Fatal(err)
	}

	setup, err := env.auth.MFASetup(ctx, meta(), login.User.UserID)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	en, err := env.auth.MFAEnable(ctx, meta(), login.User.UserID, code)
	if err != nil {
		t.Fatal(err)
	}
	if len(en.BackupCodes) == 0 {
		t.Fatal("expect backup codes")
	}

	ch2, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139001"})
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139001",
		Credential: map[string]string{"challenge_id": ch2.ChallengeID, "otp": env.sms.Code("+8613900139001")},
		Client:     service.ClientInfo{DeviceID: "dev-b"},
	})
	ae, ok := errcode.AsAppError(err)
	if !ok || ae.Code != errcode.MFARequired {
		t.Fatalf("expect MFA required, got %v", err)
	}
	mfaToken := dataString(ae.Data, "mfa_token")
	if mfaToken == "" {
		t.Fatal("missing mfa_token")
	}
	totpCode, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	done, err := env.auth.MFAComplete(ctx, meta(), service.MFACompleteDTO{
		MFAToken: mfaToken, Code: totpCode, Client: service.ClientInfo{DeviceID: "dev-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if done.Token.AccessToken == "" {
		t.Fatal("expect tokens after MFA")
	}

	totpCode, _ = totp.GenerateCode(setup.Secret, time.Now())
	su, err := env.auth.StepUp(ctx, meta(), login.User.UserID, service.StepUpDTO{
		Method: model.MethodTOTP, Credential: map[string]string{"code": totpCode},
	})
	if err != nil || su == nil || su.StepUpToken == "" {
		t.Fatalf("step-up totp failed: %v", err)
	}

	ch3, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139001"})
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139001",
		Credential: map[string]string{"challenge_id": ch3.ChallengeID, "otp": env.sms.Code("+8613900139001")},
	})
	ae, _ = errcode.AsAppError(err)
	mfaToken = dataString(ae.Data, "mfa_token")
	_, err = env.auth.MFAComplete(ctx, meta(), service.MFACompleteDTO{
		MFAToken: mfaToken, Code: en.BackupCodes[0],
	})
	if err != nil {
		t.Fatal(err)
	}
}

func dataString(data interface{}, key string) string {
	m, ok := data.(map[string]interface{})
	if !ok {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func dataBool(data interface{}, key string) bool {
	m, ok := data.(map[string]interface{})
	if !ok {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func TestIdentityMerge(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()

	ch1, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139011"})
	u1, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139011",
		Credential: map[string]string{"challenge_id": ch1.ChallengeID, "otp": env.sms.Code("+8613900139011")},
	})
	if err != nil {
		t.Fatal(err)
	}
	ch2, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139012"})
	u2, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139012",
		Credential: map[string]string{"challenge_id": ch2.ChallengeID, "otp": env.sms.Code("+8613900139012")},
	})
	if err != nil {
		t.Fatal(err)
	}

	chBind, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139012", Scene: model.SceneBind,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = env.auth.Bind(ctx, meta(), u1.User.UserID, service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139012",
		Credential: map[string]string{"challenge_id": chBind.ChallengeID, "otp": env.sms.Code("+8613900139012")},
	})
	ae, ok := errcode.AsAppError(err)
	if !ok || ae.Code != errcode.ConflictAccount {
		t.Fatalf("expect conflict, got %v", err)
	}
	if !dataBool(ae.Data, "merge_available") {
		t.Fatalf("expect merge hint, got %#v", ae.Data)
	}

	chMerge, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139012", Scene: model.SceneMerge,
	})
	if err != nil {
		t.Fatal(err)
	}
	start, err := env.auth.MergeStart(ctx, meta(), u1.User.UserID, service.MergeStartDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139012",
		Credential: map[string]string{"challenge_id": chMerge.ChallengeID, "otp": env.sms.Code("+8613900139012")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if start.SourceUserID != u2.User.UserID {
		t.Fatalf("source want %s got %s", u2.User.UserID, start.SourceUserID)
	}
	if err := env.auth.MergeConfirm(ctx, meta(), u1.User.UserID, service.MergeConfirmDTO{MergeToken: start.MergeToken}); err != nil {
		t.Fatal(err)
	}

	ch3, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139012"})
	again, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139012",
		Credential: map[string]string{"challenge_id": ch3.ChallengeID, "otp": env.sms.Code("+8613900139012")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.User.UserID != u1.User.UserID {
		t.Fatalf("after merge expect %s got %s", u1.User.UserID, again.User.UserID)
	}
}

func TestRiskLockAndUnlock(t *testing.T) {
	env := setupEnv(t)
	env.cfg.Risk.LockAfterFailures = 3
	env.cfg.Risk.LockWindowSec = 900
	env.cfg.Risk.LockDurationSec = 900
	ctx := context.Background()

	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139021"})
	res, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139021",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613900139021")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.auth.SetPassword(ctx, meta(), res.User.UserID, service.SetPasswordDTO{
		Password: "Passw0rd1", StepUpToken: env.grantStepUp(t, res.User.UserID),
	}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 4; i++ {
		_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
			Method: model.MethodPhonePassword, Identity: "13900139021",
			Credential: map[string]string{"password": "wrong"},
		})
		if !errcode.Is(err, errcode.InvalidCred) && !errcode.Is(err, errcode.RateLimited) {
			t.Fatalf("fail %d: %v", i, err)
		}
	}
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhonePassword, Identity: "13900139021",
		Credential: map[string]string{"password": "Passw0rd1"},
	})
	if !errcode.Is(err, errcode.RateLimited) {
		t.Fatalf("expect locked, got %v", err)
	}

	admin := service.NewAdminService(env.cfg, env.repos, nil, env.redis)
	if err := admin.AdminUnlock(ctx, "id", "13900139021"); err != nil {
		t.Fatal(err)
	}
	_ = admin.AdminUnlock(ctx, "ip", "127.0.0.1")
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhonePassword, Identity: "13900139021",
		Credential: map[string]string{"password": "Passw0rd1"},
	})
	if err != nil {
		t.Fatalf("expect unlock success, got %v", err)
	}
}
