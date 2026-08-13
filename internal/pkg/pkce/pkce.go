package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// ChallengeS256 计算 code_challenge = BASE64URL(SHA256(verifier))。
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyS256 校验 code_verifier 是否匹配 code_challenge。
func VerifyS256(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	return strings.TrimSpace(ChallengeS256(verifier)) == strings.TrimSpace(challenge)
}
