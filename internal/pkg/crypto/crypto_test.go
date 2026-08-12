package crypto_test

import (
	"testing"

	"github.com/davveo/unified-account-center/internal/pkg/crypto"
)

func TestPasswordHashVerify(t *testing.T) {
	hash, err := crypto.HashPassword("Passw0rd")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := crypto.VerifyPassword(hash, "Passw0rd")
	if err != nil || !ok {
		t.Fatalf("verify failed: %v %v", ok, err)
	}
	ok, err = crypto.VerifyPassword(hash, "wrong")
	if err != nil || ok {
		t.Fatalf("should fail: %v %v", ok, err)
	}
}

func TestOTPHash(t *testing.T) {
	a := crypto.HashOTP("123456")
	b := crypto.HashOTP("123456")
	c := crypto.HashOTP("000000")
	if a != b || a == c {
		t.Fatal("otp hash mismatch")
	}
}

func TestSecretHash(t *testing.T) {
	h, err := crypto.HashSecret("demo_secret")
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.VerifySecret(h, "demo_secret") {
		t.Fatal("verify secret failed")
	}
}
