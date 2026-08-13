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
	"sync"
	"time"

	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID   string   `json:"uid"`
	ClientID string   `json:"cid"`
	TenantID string   `json:"tid"`
	Roles    []string `json:"roles,omitempty"`
	Scope    string   `json:"scope,omitempty"`
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

type Manager struct {
	alg        string // HS256 | RS256
	secret     []byte
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
	issuer     string
	mu         sync.RWMutex
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

func LoadOrGenerateRSA(privatePath, publicPath string, bits int) (*rsa.PrivateKey, error) {
	if privatePath != "" {
		if data, err := os.ReadFile(privatePath); err == nil {
			block, _ := pem.Decode(data)
			if block != nil {
				if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
					return key, nil
				}
				if keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
					if key, ok := keyAny.(*rsa.PrivateKey); ok {
						return key, nil
					}
				}
			}
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
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		_ = os.WriteFile(privatePath, privPEM, 0600)
		if publicPath != "" {
			pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
			_ = os.WriteFile(publicPath, pubPEM, 0644)
		}
	}
	return key, nil
}

// NewManager 兼容旧调用：HMAC。
func NewManager(secret, issuer string) *Manager {
	return NewHMACManager(secret, issuer)
}

func (m *Manager) Alg() string { return m.alg }
func (m *Manager) Kid() string { return m.kid }

func (m *Manager) IssueAccess(userID, clientID, tenantID string, ttl time.Duration, roles []string, scope string) (token string, jti string, exp time.Time, err error) {
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
	var t *jwt.Token
	if m.alg == "RS256" {
		t = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		t.Header["kid"] = m.kid
		signed, err := t.SignedString(m.privateKey)
		return signed, jti, exp, err
	}
	t = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := t.SignedString(m.secret)
	return signed, jti, exp, err
}

func (m *Manager) ParseAccess(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA:
			if m.publicKey == nil {
				return nil, fmt.Errorf("rsa public key missing")
			}
			return m.publicKey, nil
		case *jwt.SigningMethodHMAC:
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

func (m *Manager) JWKS() JWKS {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.alg != "RS256" || m.publicKey == nil {
		return JWKS{Keys: []JWK{}}
	}
	return JWKS{Keys: []JWK{{
		Kty: "RSA",
		Kid: m.kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(m.publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.publicKey.E)).Bytes()),
	}}}
}
