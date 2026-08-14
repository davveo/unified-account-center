package uac

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims 与中台 Access JWT claim 对齐。
type AccessClaims struct {
	UserID   string   `json:"uid"`
	ClientID string   `json:"cid"`
	TenantID string   `json:"tid"`
	Roles    []string `json:"roles,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

// JWKSVerifier 拉取并缓存 JWKS，按 kid 验签（支持双钥滚动）。
type JWKSVerifier struct {
	JWKSURL    string
	Issuer     string
	HTTP       *http.Client
	CacheTTL   time.Duration
	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey
	fetchedAt  time.Time
}

func NewJWKSVerifier(jwksURL, issuer string) *JWKSVerifier {
	return &JWKSVerifier{
		JWKSURL:  jwksURL,
		Issuer:   issuer,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
		CacheTTL: 5 * time.Minute,
		keys:     map[string]*rsa.PublicKey{},
	}
}

func (v *JWKSVerifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks http %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	next := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := jwkToRSA(k)
		if err != nil {
			continue
		}
		next[k.Kid] = pub
	}
	if len(next) == 0 {
		return errors.New("jwks empty")
	}
	v.mu.Lock()
	v.keys = next
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *JWKSVerifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	need := len(v.keys) == 0 || time.Since(v.fetchedAt) > v.CacheTTL
	pub := v.keys[kid]
	v.mu.RUnlock()
	if need || pub == nil {
		if err := v.refresh(ctx); err != nil && pub == nil {
			return nil, err
		}
		v.mu.RLock()
		pub = v.keys[kid]
		// 无 kid 时回退任意一把（兼容旧 token）
		if pub == nil && kid == "" {
			for _, p := range v.keys {
				pub = p
				break
			}
		}
		v.mu.RUnlock()
	}
	if pub == nil {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return pub, nil
}

func (v *JWKSVerifier) Parse(ctx context.Context, tokenStr string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected alg")
		}
		kid, _ := t.Header["kid"].(string)
		return v.keyFor(ctx, kid)
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	if v.Issuer != "" && claims.Issuer != "" && claims.Issuer != v.Issuer {
		return nil, fmt.Errorf("issuer mismatch")
	}
	return claims, nil
}

// HTTPMiddleware 校验 Authorization Bearer，将 claims 放入 context。
func (v *JWKSVerifier) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		claims, err := v.Parse(r.Context(), strings.TrimPrefix(h, "Bearer "))
		if err != nil {
			http.Error(w, `{"message":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxClaimsKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type ctxClaimsKey struct{}

func ClaimsFromContext(ctx context.Context) (*AccessClaims, bool) {
	c, ok := ctx.Value(ctxClaimsKey{}).(*AccessClaims)
	return c, ok
}

func jwkToRSA(k jwkKey) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	var e int
	for _, b := range eb {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}
