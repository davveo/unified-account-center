package identity_test

import (
	"testing"

	"github.com/davveo/unified-account-center/internal/pkg/identity"
)

func TestNormalizePhone(t *testing.T) {
	got, err := identity.NormalizePhone("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	if got != "+8613800138000" {
		t.Fatalf("got %s", got)
	}
	got, err = identity.NormalizePhone("+8613800138000")
	if err != nil || got != "+8613800138000" {
		t.Fatalf("got %s err=%v", got, err)
	}
}

func TestNormalizeEmail(t *testing.T) {
	got, err := identity.NormalizeEmail("  Foo.Bar@Example.COM ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "foo.bar@example.com" {
		t.Fatalf("got %s", got)
	}
}

func TestMask(t *testing.T) {
	if identity.MaskPhone("+8613800138000") != "138****8000" {
		t.Fatal(identity.MaskPhone("+8613800138000"))
	}
	if identity.MaskEmail("ab@x.com") == "" {
		t.Fatal("empty mask")
	}
}
