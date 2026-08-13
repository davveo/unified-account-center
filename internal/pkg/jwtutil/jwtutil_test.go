package jwtutil_test

import (
	"testing"
	"time"

	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
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
