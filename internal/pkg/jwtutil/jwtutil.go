package jwtutil

import (
	"fmt"
	"time"

	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID   string `json:"uid"`
	ClientID string `json:"cid"`
	TenantID string `json:"tid"`
	jwt.RegisteredClaims
}

type Manager struct {
	secret []byte
	issuer string
}

func NewManager(secret, issuer string) *Manager {
	return &Manager{secret: []byte(secret), issuer: issuer}
}

func (m *Manager) IssueAccess(userID, clientID, tenantID string, ttl time.Duration) (token string, jti string, exp time.Time, err error) {
	jti = idgen.New("at")
	exp = time.Now().Add(ttl)
	claims := Claims{
		UserID:   userID,
		ClientID: clientID,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			Audience:  []string{clientID},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := t.SignedString(m.secret)
	return signed, jti, exp, err
}

func (m *Manager) ParseAccess(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return m.secret, nil
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
