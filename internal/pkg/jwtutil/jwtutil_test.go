package jwtutil_test

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
	"github.com/golang-jwt/jwt/v5"
)

func TestIssueAndParse(t *testing.T) {
	m := jwtutil.NewManager("secret", "issuer")
	tok, jti, _, err := m.IssueAccess("u1", "c1", "default", time.Hour, []string{"user"}, "user")
	if err != nil || tok == "" || jti == "" {
		t.Fatal(err)
	}
	claims, err := m.ParseAccess(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "u1" || claims.ClientID != "c1" || len(claims.Roles) != 1 {
		t.Fatalf("%+v", claims)
	}
}

func TestRSADualKeyRotateVerifyOnly(t *testing.T) {
	k1, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	m := jwtutil.NewRSAManager(k1, "issuer", "rsa-1")

	oldTok, _, _, err := m.IssueAccess("u1", "c1", "default", time.Hour, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if kidFrom(t, oldTok) != "rsa-1" {
		t.Fatalf("want kid rsa-1")
	}

	k2, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RotateRSA(k2, "rsa-2"); err != nil {
		t.Fatal(err)
	}

	st := m.Status()
	if !st.DualKey || st.CurrentKid != "rsa-2" || st.PreviousKid != "rsa-1" {
		t.Fatalf("status=%+v", st)
	}
	jwks := m.JWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("jwks keys=%d", len(jwks.Keys))
	}

	// 旧 token：只验不签路径仍可用
	if _, err := m.ParseAccess(oldTok); err != nil {
		t.Fatalf("old token should verify: %v", err)
	}

	newTok, _, _, err := m.IssueAccess("u2", "c1", "default", time.Hour, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if kidFrom(t, newTok) != "rsa-2" {
		t.Fatalf("new token must use current kid")
	}
	if _, err := m.ParseAccess(newTok); err != nil {
		t.Fatal(err)
	}

	// 下线旧钥后旧 token 不可验
	m.ClearPreviousRSA()
	if _, err := m.ParseAccess(oldTok); err == nil {
		t.Fatal("expected old token reject after retire")
	}
	if len(m.JWKS().Keys) != 1 {
		t.Fatalf("jwks after retire=%d", len(m.JWKS().Keys))
	}
}

func TestSetPreviousRSABootPath(t *testing.T) {
	k1, _ := rsa.GenerateKey(rand.Reader, 1024)
	k0, _ := rsa.GenerateKey(rand.Reader, 1024)
	m := jwtutil.NewRSAManager(k1, "issuer", "rsa-1")
	if err := m.SetPreviousRSA(&k0.PublicKey, "rsa-0", nil); err != nil {
		t.Fatal(err)
	}
	// 手工签一个旧 kid 的 token
	claims := jwtutil.Claims{
		UserID: "u", ClientID: "c", TenantID: "t",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "issuer", Subject: "u", Audience: []string{"c"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        "jti-old",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "rsa-0"
	signed, err := tok.SignedString(k0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ParseAccess(signed); err != nil {
		t.Fatal(err)
	}
}

func TestSiblingPrevPathAndKidFile(t *testing.T) {
	if got := jwtutil.SiblingPrevPath("configs/keys/jwt_rsa.pem"); got != "configs/keys/jwt_rsa.prev.pem" {
		t.Fatalf("got %s", got)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "k.pem")
	if err := jwtutil.WriteKidFile(path, "rsa-9"); err != nil {
		t.Fatal(err)
	}
	if jwtutil.ReadKidFile(path) != "rsa-9" {
		t.Fatal(jwtutil.ReadKidFile(path))
	}
	jwtutil.RemoveKidFile(path)
	if _, err := os.Stat(path + ".kid"); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func kidFrom(t *testing.T, token string) string {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, &jwtutil.Claims{})
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := parsed.Header["kid"].(string)
	return kid
}
