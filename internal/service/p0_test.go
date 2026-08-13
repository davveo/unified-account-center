package service_test

import (
	"context"
	"testing"

	"github.com/davveo/unified-account-center/internal/adapter/oauth"
	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/pkce"
	"github.com/davveo/unified-account-center/internal/service"
)

func TestHostedCodeExchangeWithPKCE(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	app, _ := env.repos.App.FindByClientID(ctx, "app_test")
	app.RequirePKCE = true
	_ = env.repos.App.Update(ctx, app)

	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13300133000"})
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13300133000",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613300133000")},
		Client:     service.ClientInfo{DeviceID: "dev_a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if login.Token.DeviceID == "" || login.Token.RefreshJTI == "" {
		t.Fatal("expect device_id and refresh_jti in token")
	}

	verifier := "pkce-verifier-0123456789abcdef"
	challenge := pkce.ChallengeS256(verifier)
	issued, err := env.auth.IssueHostedCode(ctx, meta(), login.User.UserID, login.Token, login.Token.DeviceID, service.IssueHostedCodeDTO{
		RedirectURI: "http://localhost/cb", State: "st1", CodeChallenge: challenge,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = env.auth.ExchangeToken(ctx, meta(), service.ExchangeTokenDTO{
		GrantType: "authorization_code", Code: issued.Code, RedirectURI: "http://localhost/cb", CodeVerifier: "wrong",
	})
	if !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect pkce fail, got %v", err)
	}

	ex, err := env.auth.ExchangeToken(ctx, meta(), service.ExchangeTokenDTO{
		GrantType: "authorization_code", Code: issued.Code, RedirectURI: "http://localhost/cb", CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ex.Token.AccessToken == "" || ex.DeviceID != "dev_a" {
		t.Fatalf("bad exchange result: %+v", ex)
	}

	_, err = env.auth.ExchangeToken(ctx, meta(), service.ExchangeTokenDTO{
		GrantType: "authorization_code", Code: issued.Code, RedirectURI: "http://localhost/cb", CodeVerifier: verifier,
	})
	if err == nil {
		t.Fatal("expect code reuse rejected")
	}
}

func TestSessionListAndRevokeOthers(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13400134001"})
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13400134001",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613400134001")},
		Client:     service.ClientInfo{DeviceID: "phone"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ch2, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13400134001"})
	login2, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13400134001",
		Credential: map[string]string{"challenge_id": ch2.ChallengeID, "otp": env.sms.Code("+8613400134001")},
		Client:     service.ClientInfo{DeviceID: "pad"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := env.auth.ListSessions(ctx, meta(), login.User.UserID, login2.Token.RefreshJTI)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) < 2 {
		t.Fatalf("expect >=2 sessions, got %d", len(sessions))
	}
	if err := env.auth.RevokeOtherSessions(ctx, meta(), login.User.UserID, login2.Token.RefreshJTI); err != nil {
		t.Fatal(err)
	}
	sessions, _ = env.auth.ListSessions(ctx, meta(), login.User.UserID, login2.Token.RefreshJTI)
	if len(sessions) != 1 || sessions[0].JTI != login2.Token.RefreshJTI {
		t.Fatalf("expect only current session, got %+v", sessions)
	}
	_, err = env.auth.Refresh(ctx, meta(), login.Token.RefreshToken)
	if err == nil {
		t.Fatal("old device refresh should fail")
	}
}

func TestOAuthRequirePKCE(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	app, _ := env.repos.App.FindByClientID(ctx, "app_test")
	app.RequirePKCE = true
	app.AllowedMethods = append(app.AllowedMethods, model.MethodOAuth2)
	app.OAuthProviders = []string{"github"}
	_ = env.repos.App.Update(ctx, app)

	reg := oauth.NewRegistry(map[string]config.OAuthProviderConfig{
		"github": {ClientID: "x", ClientSecret: "y", AuthURL: "https://example.com/a", TokenURL: "https://example.com/t", UserInfoURL: "https://example.com/u"},
	})
	oauthSvc := service.NewOAuthService(env.repos, reg, env.auth, env.redis)
	env.auth.SetOAuth(oauthSvc)

	_, err := oauthSvc.Start(ctx, "app_test", "github", "http://localhost/cb", "", "", "")
	if !errcode.Is(err, errcode.BadRequest) {
		t.Fatalf("expect pkce required: %v", err)
	}
	_, err = oauthSvc.Start(ctx, "app_test", "github", "http://localhost/cb", "", "challenge", "")
	if err != nil {
		t.Fatal(err)
	}
}
