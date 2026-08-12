package identity

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	phoneLoose = regexp.MustCompile(`^\+?[0-9]{7,15}$`)
	emailLoose = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// NormalizePhone 将手机号规范为 E.164；国内 11 位默认补 +86。
func NormalizePhone(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	if s == "" {
		return "", fmt.Errorf("empty phone")
	}
	if strings.HasPrefix(s, "00") {
		s = "+" + s[2:]
	}
	if !strings.HasPrefix(s, "+") {
		if len(s) == 11 && strings.HasPrefix(s, "1") {
			s = "+86" + s
		} else {
			return "", fmt.Errorf("phone must be E.164 or CN mobile")
		}
	}
	if !phoneLoose.MatchString(s) {
		return "", fmt.Errorf("invalid phone")
	}
	return s, nil
}

func NormalizeEmail(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || !emailLoose.MatchString(s) {
		return "", fmt.Errorf("invalid email")
	}
	return s, nil
}

func MaskPhone(phone string) string {
	if len(phone) < 7 {
		return "****"
	}
	// +8613800138000 -> 138****8000 展示时去掉国家码偏好国内展示
	local := phone
	if strings.HasPrefix(phone, "+86") && len(phone) == 14 {
		local = phone[3:]
	}
	if len(local) >= 7 {
		return local[:3] + "****" + local[len(local)-4:]
	}
	return "****"
}

func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "****"
	}
	name := parts[0]
	if len(name) <= 2 {
		return "**@" + parts[1]
	}
	return name[:1] + "***" + name[len(name)-1:] + "@" + parts[1]
}
