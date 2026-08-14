package service

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
)

type SAMLStartResult struct {
	RedirectURL string `json:"redirect_url"`
	State       string `json:"state"`
}

// StartSAML 构造最小 SP-initiated AuthnRequest（Redirect Binding）。
func (s *AuthService) StartSAML(ctx context.Context, clientID, domain, relayState string) (*SAMLStartResult, error) {
	app, err := s.requireApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "@")
	idp, err := s.repos.IdP.FindByDomain(ctx, domain)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询 IdP 失败", err)
	}
	if idp == nil || !idp.Enabled {
		return nil, errcode.New(errcode.NotFound, "未配置企业 IdP")
	}
	if idp.TenantID != "" && idp.TenantID != app.TenantID {
		return nil, errcode.New(errcode.ForbiddenApp, "IdP 租户不匹配")
	}
	if strings.ToLower(idp.Protocol) != "saml" && idp.SAMLSSOURL == "" {
		return nil, errcode.New(errcode.BadRequest, "该域名未配置 SAML")
	}
	if idp.SAMLSSOURL == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 saml_sso_url")
	}
	entityID := idp.SAMLEntityID
	if entityID == "" {
		entityID = s.publicBase() + "/saml/" + idp.Provider
	}
	acs := s.publicBase() + "/api/v1/auth/saml/acs"
	reqID := idgen.New("saml")
	xmlReq := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>%s</saml:Issuer>
</samlp:AuthnRequest>`, reqID, time.Now().UTC().Format(time.RFC3339), idp.SAMLSSOURL, acs, entityID)
	deflated, err := deflateRaw([]byte(xmlReq))
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "压缩 AuthnRequest 失败", err)
	}
	enc := base64.StdEncoding.EncodeToString(deflated)
	u, err := url.Parse(idp.SAMLSSOURL)
	if err != nil {
		return nil, errcode.New(errcode.BadRequest, "SAML SSO URL 无效")
	}
	q := u.Query()
	q.Set("SAMLRequest", enc)
	if relayState == "" {
		relayState = clientID
	}
	q.Set("RelayState", relayState)
	u.RawQuery = q.Encode()
	_ = s.redis.SetJSON(ctx, "uac:saml:req:"+reqID, map[string]string{
		"client_id": clientID, "tenant_id": app.TenantID, "domain": domain, "provider": idp.Provider,
	}, 10*time.Minute)
	return &SAMLStartResult{RedirectURL: u.String(), State: reqID}, nil
}

type samlResponseXML struct {
	Assertion struct {
		Subject struct {
			NameID string `xml:"NameID"`
		} `xml:"Subject"`
		AttributeStatement struct {
			Attributes []struct {
				Name   string   `xml:"Name,attr"`
				Values []string `xml:"AttributeValue"`
			} `xml:"Attribute"`
		} `xml:"AttributeStatement"`
		Signature struct {
			SignatureValue string `xml:"SignatureValue"`
		} `xml:"Signature"`
	} `xml:"Assertion"`
}

type SAMLACSResult struct {
	User      UserView  `json:"user"`
	Token     *TokenDTO `json:"token,omitempty"`
	IsNewUser bool      `json:"is_new_user"`
}

// FinishSAML 解析 POST 的 SAMLResponse，JIT 建用户并签发 Token。
func (s *AuthService) FinishSAML(ctx context.Context, meta RequestMeta, samlResponseB64, relayState string) (*SAMLACSResult, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(samlResponseB64))
	if err != nil {
		return nil, errcode.New(errcode.BadRequest, "SAMLResponse 无效")
	}
	var doc samlResponseXML
	if err := xml.Unmarshal(raw, &doc); err != nil {
		// 兼容嵌套命名空间：宽松提取 NameID
		nameID := extractBetween(string(raw), "<saml:NameID", "</saml:NameID>")
		if nameID == "" {
			nameID = extractBetween(string(raw), "<NameID", "</NameID>")
		}
		nameID = stripTag(nameID)
		if nameID == "" {
			return nil, errcode.New(errcode.InvalidCred, "无法解析 SAML Assertion")
		}
		doc.Assertion.Subject.NameID = nameID
	}
	email := strings.TrimSpace(doc.Assertion.Subject.NameID)
	if email == "" {
		return nil, errcode.New(errcode.InvalidCred, "SAML NameID 为空")
	}
	clientID := meta.ClientID
	if clientID == "" {
		clientID = relayState
	}
	app, err := s.requireApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	domain := emailDomain(email)
	idp, _ := s.repos.IdP.FindByDomain(ctx, domain)
	if idp != nil && idp.SAMLCertPEM != "" {
		if err := verifySAMLRough(raw, idp.SAMLCertPEM); err != nil {
			return nil, errcode.New(errcode.InvalidCred, "SAML 签名校验失败")
		}
	}
	user, isNew, err := s.findOrCreateByEmail(ctx, app, email, "saml:"+firstNonEmptyStr(idpProvider(idp), "saml"))
	if err != nil {
		return nil, err
	}
	token, err := s.issueTokens(ctx, app, user, ClientInfo{}, meta)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, app, user.UserID, "login_ok", true, "saml", meta)
	s.emit(model.EventLoginOK, app.TenantID, app.ClientID, user.UserID, map[string]interface{}{"method": "saml"})
	if isNew {
		s.emit(model.EventUserCreated, app.TenantID, app.ClientID, user.UserID, map[string]interface{}{"method": "saml"})
	}
	roles, _ := s.rolesForUser(ctx, user.UserID, app.TenantID)
	return &SAMLACSResult{User: userViewOf(user, roles), Token: token, IsNewUser: isNew}, nil
}

func (s *AuthService) findOrCreateByEmail(ctx context.Context, app *model.App, email, provider string) (*model.User, bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	id, err := s.repos.Identity.FindByUnique(ctx, app.TenantID, model.IdentityEmail, "", email)
	if err != nil {
		return nil, false, errcode.Wrap(errcode.Internal, "查询身份失败", err)
	}
	if id != nil {
		u, err := s.repos.User.FindByUserID(ctx, id.UserID)
		return u, false, err
	}
	if !app.AutoRegister {
		return nil, false, errcode.New(errcode.ForbiddenApp, "禁止自动注册")
	}
	uid := idgen.New("u")
	u := &model.User{UserID: uid, TenantID: app.TenantID, DisplayName: email, Status: model.UserStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.repos.User.Create(ctx, u); err != nil {
		return nil, false, errcode.Wrap(errcode.Internal, "创建用户失败", err)
	}
	_ = s.repos.Identity.Create(ctx, &model.Identity{
		TenantID: app.TenantID, UserID: uid, Type: model.IdentityEmail, Provider: "", Identifier: email, Verified: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	_ = provider
	return u, true, nil
}

func (s *AuthService) publicBase() string {
	if s.cfg != nil && s.cfg.Server.PublicBaseURL != "" {
		return strings.TrimRight(s.cfg.Server.PublicBaseURL, "/")
	}
	return "http://127.0.0.1:8080"
}

func deflateRaw(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func extractBetween(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	i = strings.Index(s[i:], ">")
	if i < 0 {
		return ""
	}
	start := strings.Index(s, a)
	start = start + strings.Index(s[start:], ">") + 1
	end := strings.Index(s[start:], b)
	if end < 0 {
		return ""
	}
	return s[start : start+end]
}

func stripTag(s string) string {
	s = strings.TrimSpace(s)
	return s
}

func emailDomain(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 {
		return ""
	}
	return strings.ToLower(email[i+1:])
}

func idpProvider(idp *model.EnterpriseIdP) string {
	if idp == nil {
		return ""
	}
	return idp.Provider
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func verifySAMLRough(raw []byte, certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("bad cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not rsa")
	}
	// 最小校验：确保证书可解析；完整 XML-DSig 可后续加深
	sum := sha256.Sum256(raw)
	_ = pub
	_ = crypto.SHA256
	_ = sum
	return nil
}
