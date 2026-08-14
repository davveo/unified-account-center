package jwtutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID             string   `json:"uid"`
	ClientID           string   `json:"cid"`
	TenantID           string   `json:"tid"`
	Roles              []string `json:"roles,omitempty"`
	Scope              string   `json:"scope,omitempty"`
	MustChangePassword bool     `json:"mcp,omitempty"` // 强制改密
	UserVersion        int64    `json:"uv,omitempty"`  // 强退版本号
	jwt.RegisteredClaims
}

// IDTokenClaims OIDC id_token（标准 iss/sub/aud/exp/iat + 可选 auth_time、uid/tid）。
type IDTokenClaims struct {
	UserID   string `json:"uid,omitempty"`
	TenantID string `json:"tid,omitempty"`
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	jwt.RegisteredClaims
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Status 描述当前签名/验证密钥状态（管理端展示用）。
type Status struct {
	Alg         string `json:"alg"`
	CurrentKid  string `json:"current_kid"`
	PreviousKid string `json:"previous_kid,omitempty"`
	DualKey     bool   `json:"dual_key"`
}

type Manager struct {
	alg         string // HS256 | RS256
	secret      []byte
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	kid         string
	prevPrivate *rsa.PrivateKey // 仅用于落盘；验签只用 prevPublic
	prevPublic  *rsa.PublicKey
	prevKid     string
	issuer      string
	mu          sync.RWMutex
}

func NewHMACManager(secret, issuer string) *Manager {
	return &Manager{alg: "HS256", secret: []byte(secret), issuer: issuer, kid: "hmac"}
}

func NewRSAManager(privateKey *rsa.PrivateKey, issuer, kid string) *Manager {
	if kid == "" {
		kid = "rsa-1"
	}
	return &Manager{
		alg:        "RS256",
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		kid:        kid,
		issuer:     issuer,
	}
}

// SetPreviousRSA 设置只验不签的旧钥（启动时从配置加载）。
func (m *Manager) SetPreviousRSA(publicKey *rsa.PublicKey, kid string, privateKey *rsa.PrivateKey) error {
	if m == nil || m.alg != "RS256" {
		return fmt.Errorf("previous key only supported for RS256")
	}
	if publicKey == nil && privateKey != nil {
		publicKey = &privateKey.PublicKey
	}
	if publicKey == nil {
		return fmt.Errorf("previous public key required")
	}
	if kid == "" {
		return fmt.Errorf("previous kid required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if kid == m.kid {
		return fmt.Errorf("previous kid must differ from current kid")
	}
	m.prevPublic = publicKey
	m.prevPrivate = privateKey
	m.prevKid = kid
	return nil
}

// ClearPreviousRSA 下线旧钥：JWKS 与验签不再接受 previous kid。
func (m *Manager) ClearPreviousRSA() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prevPrivate = nil
	m.prevPublic = nil
	m.prevKid = ""
}

// RotateRSA 将当前钥降为 previous（只验不签），新钥成为唯一签名钥。
func (m *Manager) RotateRSA(newKey *rsa.PrivateKey, newKid string) error {
	if m == nil || m.alg != "RS256" {
		return fmt.Errorf("rotate only supported for RS256")
	}
	if newKey == nil {
		return fmt.Errorf("new private key required")
	}
	if newKid == "" {
		newKid = fmt.Sprintf("rsa-%d", time.Now().Unix())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.privateKey == nil || m.publicKey == nil {
		return fmt.Errorf("current rsa key missing")
	}
	if newKid == m.kid {
		return fmt.Errorf("new kid must differ from current kid")
	}
	m.prevPrivate = m.privateKey
	m.prevPublic = m.publicKey
	m.prevKid = m.kid
	m.privateKey = newKey
	m.publicKey = &newKey.PublicKey
	m.kid = newKid
	return nil
}

func LoadOrGenerateRSA(privatePath, publicPath string, bits int) (*rsa.PrivateKey, error) {
	if privatePath != "" {
		if key, err := LoadRSAPrivateKey(privatePath); err == nil {
			return key, nil
		}
	}
	if bits <= 0 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	if privatePath != "" {
		if err := WriteRSAKeyPair(key, privatePath, publicPath); err != nil {
			return nil, err
		}
	}
	return key, nil
}

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key: %s", path)
	}
	return key, nil
}

func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	switch block.Type {
	case "PUBLIC KEY":
		pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key: %s", path)
		}
		return pub, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &key.PublicKey, nil
	case "PRIVATE KEY":
		keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := keyAny.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key: %s", path)
		}
		return &key.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q in %s", block.Type, path)
	}
}

func WriteRSAKeyPair(key *rsa.PrivateKey, privatePath, publicPath string) error {
	if key == nil {
		return fmt.Errorf("nil private key")
	}
	if privatePath != "" {
		if err := os.MkdirAll(filepath.Dir(privatePath), 0o755); err != nil {
			return err
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		if err := os.WriteFile(privatePath, privPEM, 0600); err != nil {
			return err
		}
	}
	if publicPath != "" {
		if err := os.MkdirAll(filepath.Dir(publicPath), 0o755); err != nil {
			return err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		if err := os.WriteFile(publicPath, pubPEM, 0644); err != nil {
			return err
		}
	}
	return nil
}

// SiblingPrevPath 在扩展名前插入 .prev，例如 a.pem → a.prev.pem。
func SiblingPrevPath(path string) string {
	if path == "" {
		return ""
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	if ext == "" {
		return path + ".prev"
	}
	return base + ".prev" + ext
}

// NewManager 兼容旧调用：HMAC。
func NewManager(secret, issuer string) *Manager {
	return NewHMACManager(secret, issuer)
}

func (m *Manager) Alg() string { return m.alg }

func (m *Manager) Kid() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kid
}

func (m *Manager) PreviousKid() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.prevKid
}

func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Status{
		Alg:         m.alg,
		CurrentKid:  m.kid,
		PreviousKid: m.prevKid,
		DualKey:     m.alg == "RS256" && m.prevPublic != nil && m.prevKid != "",
	}
}

// SnapshotKeys 返回当前/旧钥材料的浅拷贝，供落盘使用。
func (m *Manager) SnapshotKeys() (currPriv, prevPriv *rsa.PrivateKey, currKid, prevKid string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.privateKey, m.prevPrivate, m.kid, m.prevKid
}

// AccessOption 签发可选参数。
type AccessOption func(*Claims)

func WithMustChangePassword(v bool) AccessOption {
	return func(c *Claims) { c.MustChangePassword = v }
}

func WithUserVersion(v int64) AccessOption {
	return func(c *Claims) { c.UserVersion = v }
}

// IDTokenOption 签发 id_token 可选参数。
type IDTokenOption func(*IDTokenClaims)

func WithAuthTime(t time.Time) IDTokenOption {
	return func(c *IDTokenClaims) {
		c.AuthTime = jwt.NewNumericDate(t)
	}
}

func (m *Manager) signClaims(claims jwt.Claims) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.alg == "RS256" {
		if m.privateKey == nil {
			return "", fmt.Errorf("rsa private key missing")
		}
		t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		t.Header["kid"] = m.kid
		return t.SignedString(m.privateKey)
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(m.secret)
}

func (m *Manager) IssueAccess(userID, clientID, tenantID string, ttl time.Duration, roles []string, scope string, opts ...AccessOption) (token string, jti string, exp time.Time, err error) {
	jti = idgen.New("at")
	exp = time.Now().Add(ttl)
	if roles == nil {
		roles = []string{}
	}
	claims := Claims{
		UserID:   userID,
		ClientID: clientID,
		TenantID: tenantID,
		Roles:    append([]string{}, roles...),
		Scope:    scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			Audience:  []string{clientID},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&claims)
		}
	}
	signed, err := m.signClaims(claims)
	return signed, jti, exp, err
}

// IssueIDToken 签发 OIDC id_token，复用与 access_token 相同的签名钥与 kid。
func (m *Manager) IssueIDToken(userID, clientID, tenantID string, ttl time.Duration, opts ...IDTokenOption) (token string, jti string, exp time.Time, err error) {
	jti = idgen.New("id")
	now := time.Now()
	exp = now.Add(ttl)
	claims := IDTokenClaims{
		UserID:   userID,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&claims)
		}
	}
	signed, err := m.signClaims(claims)
	return signed, jti, exp, err
}

func (m *Manager) ParseAccess(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA:
			return m.keyFuncRSA(t)
		case *jwt.SigningMethodHMAC:
			m.mu.RLock()
			defer m.mu.RUnlock()
			if len(m.secret) == 0 {
				return nil, fmt.Errorf("hmac secret missing")
			}
			return m.secret, nil
		default:
			return nil, fmt.Errorf("unexpected signing method")
		}
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func (m *Manager) ParseIDToken(tokenStr string) (*IDTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &IDTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA:
			return m.keyFuncRSA(t)
		case *jwt.SigningMethodHMAC:
			m.mu.RLock()
			defer m.mu.RUnlock()
			if len(m.secret) == 0 {
				return nil, fmt.Errorf("hmac secret missing")
			}
			return m.secret, nil
		default:
			return nil, fmt.Errorf("unexpected signing method")
		}
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*IDTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid id_token")
	}
	return claims, nil
}

func (m *Manager) keyFuncRSA(t *jwt.Token) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	kid, _ := t.Header["kid"].(string)
	switch {
	case kid == "" || kid == m.kid:
		if m.publicKey == nil {
			return nil, fmt.Errorf("rsa public key missing")
		}
		return m.publicKey, nil
	case kid == m.prevKid && m.prevPublic != nil:
		return m.prevPublic, nil
	default:
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
}

func (m *Manager) JWKS() JWKS {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.alg != "RS256" {
		return JWKS{Keys: []JWK{}}
	}
	keys := make([]JWK, 0, 2)
	if m.publicKey != nil {
		keys = append(keys, jwkFromPublic(m.publicKey, m.kid))
	}
	if m.prevPublic != nil && m.prevKid != "" {
		keys = append(keys, jwkFromPublic(m.prevPublic, m.prevKid))
	}
	return JWKS{Keys: keys}
}

func jwkFromPublic(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ReadKidFile 读取 keyPath.kid 旁路文件。
func ReadKidFile(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	b, err := os.ReadFile(keyPath + ".kid")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// WriteKidFile 写入 keyPath.kid。
func WriteKidFile(keyPath, kid string) error {
	if keyPath == "" || kid == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(keyPath+".kid", []byte(kid+"\n"), 0644)
}

// RemoveKidFile 删除旁路 kid 文件。
func RemoveKidFile(keyPath string) {
	if keyPath == "" {
		return
	}
	_ = os.Remove(keyPath + ".kid")
}
