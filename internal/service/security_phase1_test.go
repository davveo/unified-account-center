package service_test

import (
	"context"
	"testing"

	"github.com/davveo/unified-account-center/internal/adapter/oauth"
	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/service"
)

func TestAutoRegisterNotOverridableByClient(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()

	// 关闭自动注册
	app, err := env.repos.App.FindByClientID(ctx, "app_test")
	if err != nil || app == nil {
		t.Fatal(err)
	}
	app.AutoRegister = false
	if err := env.repos.App.Update(ctx, app); err != nil {
		t.Fatal(err)
	}

	ch, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13300133000",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method:   model.MethodPhoneOTP,
		Identity: "13300133000",
		Credential: map[string]string{
			"challenge_id": ch.ChallengeID,
			"otp":          env.sms.Code("+8613300133000"),
		},
		// 即便旧客户端传 options，也不应生效（字段已移除）
	})
	if !errcode.Is(err, errcode.PendingApproval) && !errcode.Is(err, errcode.NotFound) {
		t.Fatalf("expect pending approval or not found when auto_register=false, got %v", err)
	}
	if ae, ok := errcode.AsAppError(err); ok && ae.Code == errcode.PendingApproval {
		if ae.Data == nil {
			t.Fatal("expect join_request hint")
		}
	}
}

func TestPasswordFailRateLimit(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()

	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13200132000"})
	res, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13200132000",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613200132000")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.auth.SetPassword(ctx, meta(), res.User.UserID, service.SetPasswordDTO{
		Password: "Passw0rd1", StepUpToken: env.grantStepUp(t, res.User.UserID),
	}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
			Method: model.MethodPhonePassword, Identity: "13200132000",
			Credential: map[string]string{"password": "wrong"},
		})
		if !errcode.Is(err, errcode.InvalidCred) {
			t.Fatalf("expect invalid cred on fail %d: %v", i, err)
		}
	}
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhonePassword, Identity: "13200132000",
		Credential: map[string]string{"password": "Passw0rd1"},
	})
	if !errcode.Is(err, errcode.RateLimited) {
		t.Fatalf("expect rate limited, got %v", err)
	}
}

func TestSetPasswordRevokesRefresh(t *testing.T) {
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
	if err := env.auth.SetPassword(ctx, meta(), login.User.UserID, service.SetPasswordDTO{
		Password: "Passw0rd1", StepUpToken: env.grantStepUp(t, login.User.UserID),
	}); err != nil {
		t.Fatal(err)
	}
	_, err = env.auth.Refresh(ctx, meta(), oldRT)
	if !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect refresh revoked after set password, got %v", err)
	}
}

func TestRedirectAllowedExactOnly(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	app, _ := env.repos.App.FindByClientID(ctx, "app_test")
	app.AllowedMethods = append(app.AllowedMethods, model.MethodOAuth2)
	app.RedirectURIs = []string{"http://localhost/cb"}
	app.OAuthProviders = []string{"github"}
	_ = env.repos.App.Update(ctx, app)

	oauthSvc := service.NewOAuthService(env.repos, oauth.NewRegistry(map[string]config.OAuthProviderConfig{
		"github": {ClientID: "x", ClientSecret: "y", AuthURL: "https://example.com/a", TokenURL: "https://example.com/t", UserInfoURL: "https://example.com/u"},
	}), env.auth, env.redis)
	env.auth.SetOAuth(oauthSvc)

	_, err := oauthSvc.Start(ctx, "app_test", "github", "http://localhost/cb.evil", "", "", "")
	if !errcode.Is(err, errcode.BadRequest) {
		t.Fatalf("prefix redirect must be rejected: %v", err)
	}
	_, err = oauthSvc.Start(ctx, "app_test", "github", "http://localhost/cb", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = oauthSvc.Start(ctx, "app_test", "wechat", "http://localhost/cb", "", "", "")
	if !errcode.Is(err, errcode.ForbiddenApp) && !errcode.Is(err, errcode.BadRequest) {
		t.Fatalf("expect provider blocked: %v", err)
	}
}

func TestOAuthStateRequired(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	app, _ := env.repos.App.FindByClientID(ctx, "app_test")
	app.AllowedMethods = append(app.AllowedMethods, model.MethodOAuth2)
	app.RedirectURIs = []string{"http://localhost/cb"}
	app.OAuthProviders = []string{"github"}
	_ = env.repos.App.Update(ctx, app)

	oauthSvc := service.NewOAuthService(env.repos, oauth.NewRegistry(map[string]config.OAuthProviderConfig{
		"github": {ClientID: "x", ClientSecret: "y", AuthURL: "https://example.com/a", TokenURL: "https://example.com/t", UserInfoURL: "https://example.com/u"},
	}), env.auth, env.redis)
	env.auth.SetOAuth(oauthSvc)

	_, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method:   model.MethodOAuth2,
		Provider: "github",
		Credential: map[string]string{
			"code":         "abc",
			"redirect_uri": "http://localhost/cb",
			// missing state
		},
	})
	if !errcode.Is(err, errcode.BadRequest) && !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect state required, got %v", err)
	}
}
