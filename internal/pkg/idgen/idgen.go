package idgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func New(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	ts := time.Now().UnixNano()
	return fmt.Sprintf("%s_%x%s", prefix, ts, hex.EncodeToString(b))
}

func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func RandomDigits(n int) string {
	const digits = "0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	var sb strings.Builder
	sb.Grow(n)
	for i := 0; i < n; i++ {
		sb.WriteByte(digits[int(b[i])%10])
	}
	return sb.String()
}
