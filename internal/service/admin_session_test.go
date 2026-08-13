package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/davveo/unified-account-center/internal/repository"
	"github.com/davveo/unified-account-center/internal/service"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupAdminSessionEnv(t *testing.T) (*service.AdminService, *repository.Repos) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:admin_session_"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	repos := repository.NewRepos(db)
	cfg := &config.Config{
		Admin: config.AdminConfig{Token: "admin-dev-token"},
		JWT:   config.JWTConfig{AccessTTL: 3600, Issuer: "test"},
	}
	admin := service.NewAdminService(cfg, repos, nil, nil)
	admin.SetJWT(jwtutil.NewHMACManager("test-secret-for-admin-login", "test"))
	_ = admin.EnsureDefaultTenant(context.Background())
	return admin, repos
}

func TestAdminLoginByToken(t *testing.T) {
	admin, _ := setupAdminSessionEnv(t)
	sess, err := admin.AdminLogin(context.Background(), service.AdminLoginRequest{
		Mode:  "token",
		Token: "admin-dev-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.AuthType != "token" || sess.Role != model.RolePlatformAdmin {
		t.Fatalf("unexpected session: %+v", sess)
	}
	_, err = admin.AdminLogin(context.Background(), service.AdminLoginRequest{
		Mode:  "token",
		Token: "wrong",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAdminLoginByPasswordRequiresRole(t *testing.T) {
	admin, repos := setupAdminSessionEnv(t)
	ctx := context.Background()
	u := &model.User{UserID: "u_admin", TenantID: "default", DisplayName: "Ops", Status: model.UserStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := repos.User.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := repos.Identity.Create(ctx, &model.Identity{
		TenantID: "default", UserID: u.UserID, Type: model.IdentityPhone, Provider: "", Identifier: "+8613800138000",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	hash, _ := crypto.HashPassword("Passw0rd!")
	if err := repos.Credential.UpsertPassword(ctx, u.UserID, hash); err != nil {
		t.Fatal(err)
	}

	_, err := admin.AdminLogin(ctx, service.AdminLoginRequest{
		Mode: "password", Method: model.MethodPhonePassword,
		Identity: "13800138000", Password: "Passw0rd!",
	})
	if err == nil {
		t.Fatal("expected no-admin-role error")
	}

	if err := repos.Role.Upsert(ctx, &model.RoleBinding{UserID: u.UserID, TenantID: "default", Role: model.RoleOperator}); err != nil {
		t.Fatal(err)
	}
	sess, err := admin.AdminLogin(ctx, service.AdminLoginRequest{
		Mode: "password", Method: model.MethodPhonePassword,
		Identity: "13800138000", Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.AuthType != "bearer" || sess.Token == "" || sess.UserID != u.UserID {
		t.Fatalf("unexpected session: %+v", sess)
	}
}
