package errcode

import "fmt"

// 业务错误码（对齐技术方案）
const (
	OK              = 0
	BadRequest      = 40001
	Unauthorized    = 40100
	InvalidCred     = 40110
	ForbiddenApp    = 40310
	ConflictAccount = 40910
	MFARequired     = 40120
	RateLimited     = 42900
	NotFound        = 40400
	Internal        = 50000
)

var messages = map[int]string{
	OK:              "ok",
	BadRequest:      "参数错误",
	Unauthorized:    "未登录",
	InvalidCred:     "凭证无效",
	ForbiddenApp:    "应用无权限",
	ConflictAccount: "账户冲突",
	MFARequired:     "需要二次验证",
	RateLimited:     "请求过于频繁",
	NotFound:        "资源不存在",
	Internal:        "内部错误",
}

func Message(code int) string {
	if msg, ok := messages[code]; ok {
		return msg
	}
	return "unknown error"
}

type AppError struct {
	Code    int
	Message string
	Cause   error
	Data    interface{}
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *AppError) Unwrap() error { return e.Cause }

func New(code int, msg string) *AppError {
	if msg == "" {
		msg = Message(code)
	}
	return &AppError{Code: code, Message: msg}
}

func NewWithData(code int, msg string, data interface{}) *AppError {
	ae := New(code, msg)
	ae.Data = data
	return ae
}

func Wrap(code int, msg string, cause error) *AppError {
	if msg == "" {
		msg = Message(code)
	}
	return &AppError{Code: code, Message: msg, Cause: cause}
}

func Is(err error, code int) bool {
	if err == nil {
		return false
	}
	if ae, ok := err.(*AppError); ok {
		return ae.Code == code
	}
	return false
}

func AsAppError(err error) (*AppError, bool) {
	if err == nil {
		return nil, false
	}
	if ae, ok := err.(*AppError); ok {
		return ae, true
	}
	return nil, false
}
