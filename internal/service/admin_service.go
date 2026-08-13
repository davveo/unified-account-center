package service

import (
	"context"
	"sort"
	"strings"

	"github.com/davveo/unified-account-center/internal/adapter/oauth"
	"github.com/davveo/unified-account-center/internal/config"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/repository"
)

var allChannels = []ChannelInfo{
	{
		Method:        model.MethodPhoneOTP,
		Name:          "手机号验证码",
		Category:      "otp",
		Description:   "发送短信 OTP，校验通过后登录/注册",
		NeedChallenge: true,
		Testable:      true,
	},
	{
		Method:        model.MethodPhonePassword,
		Name:          "手机号密码",
		Category:      "password",
		Description:   "使用已绑定手机号 + 密码登录（需先设密）",
		NeedChallenge: false,
		Testable:      true,
	},
	{
		Method:        model.MethodEmailOTP,
		Name:          "邮箱验证码",
		Category:      "otp",
		Description:   "发送邮件 OTP，校验通过后登录/注册",
		NeedChallenge: true,
		Testable:      true,
	},
	{
		Method:        model.MethodEmailPassword,
		Name:          "邮箱密码",
		Category:      "password",
		Description:   "使用已绑定邮箱 + 密码登录（需先设密）",
		NeedChallenge: false,
		Testable:      true,
	},
	{
		Method:        model.MethodOAuth2,
		Name:          "OAuth2 / OIDC",
		Category:      "oauth",
		Description:   "第三方授权码登录（GitHub 等），需配置 Provider",
		NeedChallenge: false,
		Testable:      true,
	},
}

type ChannelInfo struct {
	Method        string   `json:"method"`
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	Description   string   `json:"description"`
	NeedChallenge bool     `json:"need_challenge"`
	Testable      bool     `json:"testable"`
	Providers     []string `json:"providers,omitempty"`
	Configured    bool     `json:"configured"` // OAuth Provider 是否已配置密钥
}

type AdminService struct {
	cfg      *config.Config
	repos    *repository.Repos
	oauthReg *oauth.Registry
}

func NewAdminService(cfg *config.Config, repos *repository.Repos, oauthReg *oauth.Registry) *AdminService {
	return &AdminService{cfg: cfg, repos: repos, oauthReg: oauthReg}
}

type CreateAppRequest struct {
	Name           string   `json:"name" binding:"required"`
	TenantID       string   `json:"tenant_id"`
	AllowedMethods []string `json:"allowed_methods"`
	RedirectURIs   []string `json:"redirect_uris"`
	OAuthProviders []string `json:"oauth_providers"`
	AutoRegister   *bool    `json:"auto_register"`
	RequirePKCE    *bool    `json:"require_pkce"`
	LoginTitle     string   `json:"login_title"`
	LogoURL        string   `json:"logo_url"`
	ThemeColor     string   `json:"theme_color"`
	AccessTTL      int64    `json:"access_ttl"`
	RefreshTTL     int64    `json:"refresh_ttl"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
}

type CreateAppResult struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // 仅创建时返回一次明文
	AppView
}

type AppView struct {
	ClientID       string   `json:"client_id"`
	Name           string   `json:"name"`
	TenantID       string   `json:"tenant_id"`
	AllowedMethods []string `json:"allowed_methods"`
	RedirectURIs   []string `json:"redirect_uris"`
	OAuthProviders []string `json:"oauth_providers"`
	AutoRegister   bool     `json:"auto_register"`
	RequirePKCE    bool     `json:"require_pkce"`
	LoginTitle     string   `json:"login_title"`
	LogoURL        string   `json:"logo_url"`
	ThemeColor     string   `json:"theme_color"`
	AccessTTL      int64    `json:"access_ttl"`
	RefreshTTL     int64    `json:"refresh_ttl"`
	Status         string   `json:"status"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
	HostedLoginURL string   `json:"hosted_login_url,omitempty"`
}

func (s *AdminService) CreateApp(ctx context.Context, req CreateAppRequest) (*CreateAppResult, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errcode.New(errcode.BadRequest, "应用名称不能为空")
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = "default"
	}
	methods := req.AllowedMethods
	if len(methods) == 0 {
		methods = []string{
			model.MethodPhoneOTP,
			model.MethodPhonePassword,
			model.MethodEmailOTP,
			model.MethodEmailPassword,
		}
	}
	for _, m := range methods {
		if !isKnownMethod(m) {
			return nil, errcode.New(errcode.BadRequest, "不支持的登录方式: "+m)
		}
	}

	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		clientID = idgen.New("app")
	}
	existing, err := s.repos.App.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询应用失败", err)
	}
	if existing != nil {
		return nil, errcode.New(errcode.ConflictAccount, "client_id 已存在")
	}

	secret := strings.TrimSpace(req.ClientSecret)
	if secret == "" {
		secret = idgen.RandomHex(24)
	}
	hash, err := crypto.HashSecret(secret)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "生成密钥失败", err)
	}

	autoReg := true
	if req.AutoRegister != nil {
		autoReg = *req.AutoRegister
	}
	accessTTL := req.AccessTTL
	if accessTTL <= 0 {
		accessTTL = s.cfg.JWT.AccessTTL
	}
	refreshTTL := req.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = s.cfg.JWT.RefreshTTL
	}
	redirects := req.RedirectURIs
	if redirects == nil {
		redirects = []string{}
	}
	providers := req.OAuthProviders
	if providers == nil {
		providers = []string{}
	}

	app := &model.App{
		ClientID:         clientID,
		ClientSecretHash: hash,
		Name:             name,
		TenantID:         tenantID,
		AllowedMethods:   methods,
		RedirectURIs:     redirects,
		OAuthProviders:   providers,
		AutoRegister:     autoReg,
		RequirePKCE:      req.RequirePKCE != nil && *req.RequirePKCE,
		LoginTitle:       strings.TrimSpace(req.LoginTitle),
		LogoURL:          strings.TrimSpace(req.LogoURL),
		ThemeColor:       strings.TrimSpace(req.ThemeColor),
		AccessTTL:        accessTTL,
		RefreshTTL:       refreshTTL,
		Status:           "active",
	}
	if err := s.repos.App.Create(ctx, app); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "创建应用失败", err)
	}
	return &CreateAppResult{
		ClientID:     clientID,
		ClientSecret: secret,
		AppView:      toAppView(app),
	}, nil
}

func (s *AdminService) ListApps(ctx context.Context, limit, offset int) ([]AppView, int64, error) {
	list, total, err := s.repos.App.List(ctx, limit, offset)
	if err != nil {
		return nil, 0, errcode.Wrap(errcode.Internal, "查询应用失败", err)
	}
	out := make([]AppView, 0, len(list))
	for i := range list {
		out = append(out, toAppView(&list[i]))
	}
	return out, total, nil
}

func (s *AdminService) GetApp(ctx context.Context, clientID string) (*AppView, error) {
	app, err := s.repos.App.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询应用失败", err)
	}
	if app == nil {
		return nil, errcode.New(errcode.NotFound, "应用不存在")
	}
	v := toAppView(app)
	return &v, nil
}

func (s *AdminService) ListChannels() []ChannelInfo {
	out := make([]ChannelInfo, 0, len(allChannels))
	configuredProviders := s.oauthReg.Names()
	sort.Strings(configuredProviders)
	for _, ch := range allChannels {
		item := ch
		if item.Method == model.MethodOAuth2 {
			item.Providers = configuredProviders
			item.Configured = len(configuredProviders) > 0
			// 也展示配置文件里声明但未填 client_id 的 provider
			declared := make([]string, 0)
			for name, cfg := range s.cfg.OAuth.Providers {
				declared = append(declared, name)
				_ = cfg
			}
			sort.Strings(declared)
			if len(declared) > 0 {
				item.Providers = declared
			}
		} else {
			item.Configured = true
		}
		out = append(out, item)
	}
	return out
}

func toAppView(app *model.App) AppView {
	return AppView{
		ClientID:       app.ClientID,
		Name:           app.Name,
		TenantID:       app.TenantID,
		AllowedMethods: append([]string{}, app.AllowedMethods...),
		RedirectURIs:   append([]string{}, app.RedirectURIs...),
		OAuthProviders: append([]string{}, app.OAuthProviders...),
		AutoRegister:   app.AutoRegister,
		RequirePKCE:    app.RequirePKCE,
		LoginTitle:     app.LoginTitle,
		LogoURL:        app.LogoURL,
		ThemeColor:     app.ThemeColor,
		AccessTTL:      app.AccessTTL,
		RefreshTTL:     app.RefreshTTL,
		Status:         app.Status,
		CreatedAt:      app.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt:      app.UpdatedAt.Format("2006-01-02 15:04:05"),
		HostedLoginURL: "/login?client_id=" + app.ClientID,
	}
}

func isKnownMethod(m string) bool {
	switch m {
	case model.MethodPhoneOTP, model.MethodPhonePassword, model.MethodEmailOTP, model.MethodEmailPassword, model.MethodOAuth2:
		return true
	default:
		return false
	}
}
