package service_test

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/davveo/unified-account-center/internal/adapter/oauth"
	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/repository"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAdminCreateAndListApps(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:admin_test?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	mr, _ := miniredis.Run()
	t.Cleanup(mr.Close)
	_ = redisx.NewWithRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}))

	cfg := &config.Config{
		JWT: config.JWTConfig{AccessTTL: 3600, RefreshTTL: 86400},
		OAuth: config.OAuthConfig{Providers: map[string]config.OAuthProviderConfig{
			"github": {ClientID: "", ClientSecret: ""},
		}},
	}
	repos := repository.NewRepos(db)
	admin := service.NewAdminService(cfg, repos, oauth.NewRegistry(cfg.OAuth.Providers), nil)

	created, err := admin.CreateApp(context.Background(), service.CreateAppRequest{
		Name:           "测试应用",
		AllowedMethods: []string{"phone_otp", "email_otp"},
		RedirectURIs:   []string{"http://localhost/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ClientID == "" || created.ClientSecret == "" {
		t.Fatalf("missing credentials: %+v", created)
	}

	_, err = admin.CreateApp(context.Background(), service.CreateAppRequest{
		Name:     "dup",
		ClientID: created.ClientID,
	})
	if !errcode.Is(err, errcode.ConflictAccount) {
		t.Fatalf("expect conflict, got %v", err)
	}

	list, total, err := admin.ListApps(context.Background(), "", 10, 0)
	if err != nil || total < 1 || len(list) < 1 {
		t.Fatalf("list failed: %v total=%d", err, total)
	}

	channels := admin.ListChannels()
	if len(channels) < 5 {
		t.Fatalf("expect channels, got %d", len(channels))
	}
}
