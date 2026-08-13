package response

import (
	"net/http"

	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/gin-gonic/gin"
)

type Body struct {
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	RequestID string      `json:"request_id"`
	Data      interface{} `json:"data,omitempty"`
}

func OK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Body{
		Code:      errcode.OK,
		Message:   "ok",
		RequestID: requestID(c),
		Data:      data,
	})
}

func Fail(c *gin.Context, code int, msg string) {
	FailData(c, code, msg, nil)
}

func FailData(c *gin.Context, code int, msg string, data interface{}) {
	if msg == "" {
		msg = errcode.Message(code)
	}
	status := http.StatusOK
	switch code {
	case errcode.Unauthorized, errcode.InvalidCred, errcode.MFARequired:
		status = http.StatusUnauthorized
	case errcode.ForbiddenApp, errcode.PendingApproval:
		status = http.StatusForbidden
	case errcode.RateLimited:
		status = http.StatusTooManyRequests
	case errcode.NotFound:
		status = http.StatusNotFound
	case errcode.ConflictAccount:
		status = http.StatusConflict
	case errcode.BadRequest:
		status = http.StatusBadRequest
	case errcode.Internal:
		status = http.StatusInternalServerError
	}
	c.JSON(status, Body{
		Code:      code,
		Message:   msg,
		RequestID: requestID(c),
		Data:      data,
	})
}

func FailErr(c *gin.Context, err error) {
	if ae, ok := errcode.AsAppError(err); ok {
		FailData(c, ae.Code, ae.Message, ae.Data)
		return
	}
	Fail(c, errcode.Internal, errcode.Message(errcode.Internal))
}

func requestID(c *gin.Context) string {
	if v, ok := c.Get("request_id"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
