package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/davveo/unified-account-center/internal/adapter"
	"github.com/davveo/unified-account-center/internal/adapter/captcha"
	"github.com/davveo/unified-account-center/internal/adapter/email"
	"github.com/davveo/unified-account-center/internal/adapter/oauth"
	"github.com/davveo/unified-account-center/internal/adapter/sms"
	"github.com/davveo/unified-account-center/internal/authenticator"
	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/handler"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/mq"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/davveo/unified-account-center/internal/pkg/observability"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/repository"
	"github.com/davveo/unified-account-center/internal/server"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Application struct {
	Cfg    *config.Config
	DB     *gorm.DB
	Redis  *redisx.Client
	MQ     mq.Producer
	Router *gin.Engine
	JWT    *jwtutil.Manager
}

func New(cfg *config.Config) (*Application, error) {
	observability.InitLogger(cfg.Server.Mode)

	db, err := openDB(cfg)
	if err != nil {
		return nil, err
	}
	if err := repository.AutoMigrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	rdb := redisx.New(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err := rdb.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}

	producer := mq.Producer(mq.NewLogProducer())
	if cfg.MQ.Enabled {
		rp, err := mq.NewRocketMQProducer(cfg.MQ)
		if err != nil {
			return nil, fmt.Errorf("rocketmq: %w", err)
		}
		producer = rp
	}

	var smsSender adapter.SMSSender = sms.NewMock()
	var emailSender adapter.EmailSender = email.NewMock()
	if cfg.SMS.Provider == "mq" {
		smsSender = sms.NewMQ(producer, cfg.MQ.SMSTopic)
	}
	if cfg.Email.Provider == "mq" {
		emailSender = email.NewMQ(producer, cfg.MQ.EmailTopic)
	}
	var captchaVerifier captcha.Verifier = captcha.NewFromConfig(cfg.Captcha)

	repos := repository.NewRepos(db)
	if err := bootstrapApp(context.Background(), cfg, repos); err != nil {
		return nil, err
	}

	oauthReg := oauth.NewRegistry(cfg.OAuth.Providers)
	loadOAuthProvidersFromDB(context.Background(), repos, oauthReg)

	jwtMgr, err := buildJWT(cfg)
	if err != nil {
		return nil, err
	}
	{
		b, _ := json.Marshal(map[string]interface{}{"msg": "jwt_ready", "alg": jwtMgr.Alg(), "kid": jwtMgr.Kid()})
		log.Println(string(b))
	}

	auths := authenticator.NewRegistry(
		authenticator.NewPhoneOTP(cfg.OTP, repos.Challenge, rdb, smsSender, captchaVerifier),
		authenticator.NewEmailOTP(cfg.OTP, repos.Challenge, rdb, emailSender, captchaVerifier),
		authenticator.NewPhonePassword(repos.Identity, repos.Credential, rdb),
		authenticator.NewEmailPassword(repos.Identity, repos.Credential, rdb),
		authenticator.NewOAuth2(oauthReg),
	)

	authSvc := service.NewAuthService(cfg, repos, auths, jwtMgr, rdb)
	oauthSvc := service.NewOAuthService(repos, oauthReg, authSvc, rdb)
	authSvc.SetOAuth(oauthSvc)
	adminSvc := service.NewAdminService(cfg, repos, oauthReg)
	h := handler.NewAuthHandler(authSvc, oauthSvc)
	adminH := handler.NewAdminHandler(adminSvc)

	router := server.NewRouter(server.Deps{
		AuthHandler:  h,
		AdminHandler: adminH,
		AuthService:  authSvc,
		JWT:          jwtMgr,
		Redis:        rdb,
		DB:           db,
		AdminToken:   cfg.Admin.Token,
		Mode:         cfg.Server.Mode,
	})

	return &Application{
		Cfg:    cfg,
		DB:     db,
		Redis:  rdb,
		MQ:     producer,
		Router: router,
		JWT:    jwtMgr,
	}, nil
}

func buildJWT(cfg *config.Config) (*jwtutil.Manager, error) {
	if cfg.JWT.Alg == "HS256" {
		return jwtutil.NewHMACManager(cfg.JWT.Secret, cfg.JWT.Issuer), nil
	}
	if cfg.JWT.PrivateKeyPath != "" {
		_ = os.MkdirAll(dirOf(cfg.JWT.PrivateKeyPath), 0o755)
	}
	key, err := jwtutil.LoadOrGenerateRSA(cfg.JWT.PrivateKeyPath, cfg.JWT.PublicKeyPath, 2048)
	if err != nil {
		return nil, fmt.Errorf("jwt rsa: %w", err)
	}
	return jwtutil.NewRSAManager(key, cfg.JWT.Issuer, cfg.JWT.Kid), nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func (a *Application) Close() {
	if a.Redis != nil {
		_ = a.Redis.Close()
	}
	if a.MQ != nil {
		_ = a.MQ.Close()
	}
	if a.DB != nil {
		sqlDB, err := a.DB.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	}
}

func openDB(cfg *config.Config) (*gorm.DB, error) {
	gcfg := &gorm.Config{Logger: logger.Default.LogMode(logger.Warn)}
	switch cfg.Database.Driver {
	case "sqlite", "sqlite3":
		return nil, fmt.Errorf("sqlite driver is only available in tests; use mysql in runtime")
	default:
		db, err := gorm.Open(mysql.Open(cfg.Database.DSN), gcfg)
		if err != nil {
			return nil, err
		}
		sqlDB, err := db.DB()
		if err != nil {
			return nil, err
		}
		sqlDB.SetMaxIdleConns(cfg.Database.MaxIdle)
		sqlDB.SetMaxOpenConns(cfg.Database.MaxOpen)
		return db, nil
	}
}

func bootstrapApp(ctx context.Context, cfg *config.Config, repos *repository.Repos) error {
	if !cfg.Bootstrap.CreateDefaultApp {
		return nil
	}
	existing, err := repos.App.FindByClientID(ctx, cfg.Bootstrap.DefaultClientID)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	hash, err := crypto.HashSecret(cfg.Bootstrap.DefaultClientSecret)
	if err != nil {
		return err
	}
	appRow := &model.App{
		ClientID:         cfg.Bootstrap.DefaultClientID,
		ClientSecretHash: hash,
		Name:             "Demo App",
		TenantID:         "default",
		AllowedMethods:   cfg.Bootstrap.DefaultAllowedMethods,
		RedirectURIs:     cfg.Bootstrap.DefaultRedirectURIs,
		OAuthProviders:   []string{"github", "wechat"},
		AutoRegister:     cfg.Bootstrap.AutoRegister,
		LoginTitle:       "Demo App 登录",
		ThemeColor:       "#1f6feb",
		AccessTTL:        cfg.JWT.AccessTTL,
		RefreshTTL:       cfg.JWT.RefreshTTL,
		Status:           "active",
	}
	if err := repos.App.Create(ctx, appRow); err != nil {
		return err
	}
	log.Printf("bootstrap default app client_id=%s", appRow.ClientID)
	return nil
}

func loadOAuthProvidersFromDB(ctx context.Context, repos *repository.Repos, reg *oauth.Registry) {
	var list []model.OAuthProviderRow
	if err := repos.DB.WithContext(ctx).Where("enabled = ?", true).Find(&list).Error; err != nil {
		return
	}
	for _, row := range list {
		if row.ClientID == "" {
			continue
		}
		reg.Upsert(row.Name, config.OAuthProviderConfig{
			Kind: row.Kind, ClientID: row.ClientID, ClientSecret: row.ClientSecret,
			AuthURL: row.AuthURL, TokenURL: row.TokenURL, UserInfoURL: row.UserInfoURL,
			Scopes: append([]string{}, row.Scopes...),
		})
	}
}
