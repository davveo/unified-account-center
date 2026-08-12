package service_test

import (
	"context"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/davveo/unified-account-center/internal/authenticator"
	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/repository"
	"github.com/davveo/unified-account-center/internal/service"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type captureSMS struct {
	mu    sync.Mutex
	codes map[string]string
}

func (s *captureSMS) SendOTP(ctx context.Context, phone, code, scene string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codes == nil {
		s.codes = map[string]string{}
	}
	s.codes[phone] = code
	return nil
}

func (s *captureSMS) Code(phone string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.codes[phone]
}

type captureEmail struct {
	mu    sync.Mutex
	codes map[string]string
}

func (s *captureEmail) SendOTP(ctx context.Context, email, code, scene string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codes == nil {
		s.codes = map[string]string{}
	}
	s.codes[email] = code
	return nil
}

func (s *captureEmail) Code(email string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.codes[email]
}

type testEnv struct {
	cfg   *config.Config
	repos *repository.Repos
	auth  *service.AuthService
	sms   *captureSMS
	email *captureEmail
	redis *redisx.Client
	mr    *miniredis.Miniredis
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redisx.NewWithRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}))

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:     "test-secret",
			Issuer:     "test",
			AccessTTL:  3600,
			RefreshTTL: 86400,
		},
		OTP: config.OTPConfig{
			Length: 6, TTL: 300, ResendInterval: 0, MaxTries: 5,
		},
		Password: config.PasswordConfig{MinLength: 8, RequireLetterNumber: true},
	}
	repos := repository.NewRepos(db)
	hash, _ := crypto.HashSecret("secret")
	_ = repos.App.Create(context.Background(), &model.App{
		ClientID:         "app_test",
		ClientSecretHash: hash,
		Name:             "test",
		TenantID:         "default",
		AllowedMethods:   []string{model.MethodPhoneOTP, model.MethodEmailOTP, model.MethodPhonePassword, model.MethodEmailPassword, model.MethodOAuth2},
		RedirectURIs:     []string{"http://localhost/cb"},
		AutoRegister:     true,
		AccessTTL:        3600,
		RefreshTTL:       86400,
		Status:           "active",
	})

	smsCap := &captureSMS{}
	emailCap := &captureEmail{}
	auths := authenticator.NewRegistry(
		authenticator.NewPhoneOTP(cfg.OTP, repos.Challenge, rdb, smsCap),
		authenticator.NewEmailOTP(cfg.OTP, repos.Challenge, rdb, emailCap),
		authenticator.NewPhonePassword(repos.Identity, repos.Credential),
		authenticator.NewEmailPassword(repos.Identity, repos.Credential),
	)
	jwtMgr := jwtutil.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer)
	authSvc := service.NewAuthService(cfg, repos, auths, jwtMgr, rdb)
	return &testEnv{cfg: cfg, repos: repos, auth: authSvc, sms: smsCap, email: emailCap, redis: rdb, mr: mr}
}

func meta() service.RequestMeta {
	return service.RequestMeta{ClientID: "app_test", IP: "127.0.0.1", UA: "test"}
}

func TestPhoneOTPLoginAndReuseUser(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()

	ch, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13800138000", Scene: model.SceneLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	code := env.sms.Code("+8613800138000")
	if code == "" {
		t.Fatal("otp not sent")
	}

	res1, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method:   model.MethodPhoneOTP,
		Identity: "13800138000",
		Credential: map[string]string{
			"challenge_id": ch.ChallengeID,
			"otp":          code,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res1.IsNewUser || res1.Token.AccessToken == "" {
		t.Fatalf("unexpected: %+v", res1)
	}

	// 重放验证码应失败
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method:   model.MethodPhoneOTP,
		Identity: "13800138000",
		Credential: map[string]string{
			"challenge_id": ch.ChallengeID,
			"otp":          code,
		},
	})
	if !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect replay fail, got %v", err)
	}

	ch2, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13800138000", Scene: model.SceneLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	code2 := env.sms.Code("+8613800138000")
	res2, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method:   model.MethodPhoneOTP,
		Identity: "13800138000",
		Credential: map[string]string{
			"challenge_id": ch2.ChallengeID,
			"otp":          code2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsNewUser || res2.User.UserID != res1.User.UserID {
		t.Fatalf("should reuse same user: %s vs %s", res1.User.UserID, res2.User.UserID)
	}
}

func TestWrongOTPAndMaxTries(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	ch, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13900139000",
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
			Method:   model.MethodPhoneOTP,
			Identity: "13900139000",
			Credential: map[string]string{
				"challenge_id": ch.ChallengeID,
				"otp":          "000000",
			},
		})
		if !errcode.Is(err, errcode.InvalidCred) {
			t.Fatalf("expect invalid cred: %v", err)
		}
	}
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method:   model.MethodPhoneOTP,
		Identity: "13900139000",
		Credential: map[string]string{
			"challenge_id": ch.ChallengeID,
			"otp":          env.sms.Code("+8613900139000"),
		},
	})
	if !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect max tries lock: %v", err)
	}
}

func TestPasswordLoginSetAndAuth(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()

	// 先 OTP 注册
	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13700137000"})
	res, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13700137000",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613700137000")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.auth.SetPassword(ctx, meta(), res.User.UserID, service.SetPasswordDTO{Password: "Passw0rd1"}); err != nil {
		t.Fatal(err)
	}
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhonePassword, Identity: "13700137000",
		Credential: map[string]string{"password": "Passw0rd1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if login.User.UserID != res.User.UserID {
		t.Fatal("user mismatch")
	}
	_, err = env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhonePassword, Identity: "13700137000",
		Credential: map[string]string{"password": "bad"},
	})
	if !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect invalid: %v", err)
	}
}

func TestBindConflictAndUnbindGuard(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()

	ch1, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13600136000"})
	if err != nil {
		t.Fatal(err)
	}
	u1, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13600136000",
		Credential: map[string]string{"challenge_id": ch1.ChallengeID, "otp": env.sms.Code("+8613600136000")},
	})
	if err != nil {
		t.Fatal(err)
	}

	ch2, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13500135000"})
	if err != nil {
		t.Fatal(err)
	}
	u2, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13500135000",
		Credential: map[string]string{"challenge_id": ch2.ChallengeID, "otp": env.sms.Code("+8613500135000")},
	})
	if err != nil {
		t.Fatal(err)
	}

	// u2 尝试绑定 u1 的手机号 -> 冲突
	ch3, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodPhoneOTP, Identity: "13600136000", Scene: model.SceneBind,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = env.auth.Bind(ctx, meta(), u2.User.UserID, service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13600136000",
		Credential: map[string]string{"challenge_id": ch3.ChallengeID, "otp": env.sms.Code("+8613600136000")},
	})
	if !errcode.Is(err, errcode.ConflictAccount) {
		t.Fatalf("expect conflict: %v", err)
	}

	// 解绑唯一身份应失败
	err = env.auth.Unbind(ctx, meta(), u1.User.UserID, service.UnbindDTO{Type: model.IdentityPhone, Value: "13600136000"})
	if !errcode.Is(err, errcode.BadRequest) {
		t.Fatalf("expect keep one identity: %v", err)
	}

	// 绑定邮箱后可解绑手机
	chEmail, err := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{
		Method: model.MethodEmailOTP, Identity: "a@example.com", Scene: model.SceneBind,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.auth.Bind(ctx, meta(), u1.User.UserID, service.LoginDTO{
		Method: model.MethodEmailOTP, Identity: "a@example.com",
		Credential: map[string]string{"challenge_id": chEmail.ChallengeID, "otp": env.email.Code("a@example.com")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.auth.Unbind(ctx, meta(), u1.User.UserID, service.UnbindDTO{Type: model.IdentityPhone, Value: "13600136000"}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshAndIntrospect(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodEmailOTP, Identity: "b@example.com"})
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodEmailOTP, Identity: "b@example.com",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.email.Code("b@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := env.auth.Introspect(ctx, login.Token.AccessToken)
	if err != nil || info["active"] != true {
		t.Fatalf("introspect: %v %+v", err, info)
	}
	newTok, err := env.auth.Refresh(ctx, meta(), login.Token.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if newTok.AccessToken == "" || newTok.RefreshToken == "" {
		t.Fatal("empty tokens")
	}
	// 旧 refresh 复用应失败
	_, err = env.auth.Refresh(ctx, meta(), login.Token.RefreshToken)
	if !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect reuse detection: %v", err)
	}
}

func TestClientIsolationOnToken(t *testing.T) {
	env := setupEnv(t)
	ctx := context.Background()
	hash, _ := crypto.HashSecret("other")
	_ = env.repos.App.Create(ctx, &model.App{
		ClientID: "app_other", ClientSecretHash: hash, Name: "other", TenantID: "default",
		AllowedMethods: []string{model.MethodPhoneOTP}, RedirectURIs: []string{}, AutoRegister: true,
		AccessTTL: 3600, RefreshTTL: 86400, Status: "active",
	})
	ch, _ := env.auth.Challenge(ctx, meta(), service.ChallengeDTO{Method: model.MethodPhoneOTP, Identity: "13400134000"})
	login, err := env.auth.Login(ctx, meta(), service.LoginDTO{
		Method: model.MethodPhoneOTP, Identity: "13400134000",
		Credential: map[string]string{"challenge_id": ch.ChallengeID, "otp": env.sms.Code("+8613400134000")},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = env.auth.Refresh(ctx, service.RequestMeta{ClientID: "app_other"}, login.Token.RefreshToken)
	if !errcode.Is(err, errcode.InvalidCred) {
		t.Fatalf("expect client isolation: %v", err)
	}
}
