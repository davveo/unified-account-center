package service_test

import (
	"context"
	"testing"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/service"
)

func TestTenantCRUDAndAppQuota(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	admin := service.NewAdminService(env.cfg, env.repos, nil, env.redis)
	_ = admin.EnsureDefaultTenant(ctx)

	ten, err := admin.CreateTenant(ctx, service.CreateTenantRequest{
		TenantID: "acme", Name: "Acme Corp", MaxApps: 1, DailyOTPLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ten.TenantID != "acme" || ten.MaxApps != 1 {
		t.Fatalf("%+v", ten)
	}

	_, err = admin.CreateApp(ctx, service.CreateAppRequest{
		Name: "App1", TenantID: "acme", AllowedMethods: []string{model.MethodPhoneOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.CreateApp(ctx, service.CreateAppRequest{
		Name: "App2", TenantID: "acme", AllowedMethods: []string{model.MethodPhoneOTP},
	})
	if !errcode.Is(err, errcode.ForbiddenApp) {
		t.Fatalf("expect quota fail, got %v", err)
	}
}

func TestInviteRegisterAndRolesInJWT(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	admin := service.NewAdminService(env.cfg, env.repos, nil, env.redis)
	_ = admin.EnsureDefaultTenant(ctx)

	app, _ := env.repos.App.FindByClientID(ctx, "app_test")
	app.AutoRegister = false
	_ = env.repos.App.Update(ctx, app)

	inv, err := admin.CreateInvite(ctx, service.CreateInviteRequest{
		TenantID: "default", ClientID: "app_test", MaxUses: 1, ExpireIn: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}

	ch, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139100"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139100",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613900139100")},
	})
	if !errcode.Is(err, errcode.PendingApproval) {
		t.Fatalf("expect pending without invite, got %v", err)
	}

	ch2, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139100"})
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139100",
		Credential: map[string]string{"challenge_id": ch2.ChallengeID, "otp": env.sms.Code("+8613900139100")},
		InviteCode: inv.Code,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !login.IsNewUser || login.Token.AccessToken == "" {
		t.Fatal("expect new user with token")
	}
	claims, err := env.jwt.ParseAccess(login.Token.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Roles) == 0 || claims.Scope == "" {
		t.Fatalf("expect roles/scope in jwt: %+v", claims)
	}
}

func TestEnterpriseSSODiscoverAndForce(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	admin := service.NewAdminService(env.cfg, env.repos, nil, env.redis)
	_ = admin.EnsureDefaultTenant(ctx)
	_, _ = admin.CreateTenant(ctx, service.CreateTenantRequest{
		TenantID: "corp", Name: "Corp", ForceSSO: true, DisableLocalPassword: true,
		SSODomains: []string{"corp.example"},
	})
	_, err := admin.UpsertEnterpriseIdP(ctx, service.UpsertIdPRequest{
		TenantID: "corp", Domain: "corp.example", Provider: "github",
	})
	if err != nil {
		t.Fatal(err)
	}
	disc, err := env.auth.DiscoverSSO(ctx, "app_test", "alice@corp.example")
	if err != nil || disc.Provider != "github" {
		t.Fatalf("discover: %+v %v", disc, err)
	}

	// force sso on tenant of app — patch app tenant
	app, _ := env.repos.App.FindByClientID(ctx, "app_test")
	app.TenantID = "corp"
	_ = env.repos.App.Update(ctx, app)
	_, err = env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13900139111"})
	if !errcode.Is(err, errcode.ForbiddenApp) {
		t.Fatalf("expect force sso block otp, got %v", err)
	}
}

func TestAdminCreateUserAndAssignRole(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	admin := service.NewAdminService(env.cfg, env.repos, nil, env.redis)
	_ = admin.EnsureDefaultTenant(ctx)
	u, err := admin.AdminCreateUser(ctx, service.CreateUserRequest{
		TenantID: "default", Phone: "13900139122", DisplayName: "Ops",
		Roles: []string{model.RoleOperator},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.TempPassword == "" || u.UserID == "" {
		t.Fatalf("%+v", u)
	}
	roles, err := admin.ListUserRoles(ctx, u.UserID)
	if err != nil || len(roles) == 0 {
		t.Fatalf("roles: %v %v", roles, err)
	}
}
