package authenticator

import (
	"context"
	"strconv"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/identity"
	"github.com/davveo/unified-account-center/internal/pkg/redisx"
	"github.com/davveo/unified-account-center/internal/repository"
	"github.com/redis/go-redis/v9"
)

const (
	pwdFailLimit  = 10
	pwdFailWindow = 15 * time.Minute
)

type PasswordAuth struct {
	method   string
	idType   string
	idRepo   repository.IdentityRepo
	credRepo repository.CredentialRepo
	redis    *redisx.Client
}

func NewPhonePassword(idRepo repository.IdentityRepo,
	credRepo repository.CredentialRepo, rdb *redisx.Client) *PasswordAuth {
	return &PasswordAuth{
		method:   model.MethodPhonePassword,
		idType:   model.IdentityPhone,
		idRepo:   idRepo,
		credRepo: credRepo,
		redis:    rdb,
	}
}

func NewEmailPassword(idRepo repository.IdentityRepo,
	credRepo repository.CredentialRepo, rdb *redisx.Client) *PasswordAuth {
	return &PasswordAuth{
		method:   model.MethodEmailPassword,
		idType:   model.IdentityEmail,
		idRepo:   idRepo,
		credRepo: credRepo,
		redis:    rdb,
	}
}

func (a *PasswordAuth) Method() string { return a.method }

func (a *PasswordAuth) Challenge(ctx context.Context, req ChallengeRequest) (*ChallengeResult, error) {
	return &ChallengeResult{}, nil
}

func (a *PasswordAuth) Verify(ctx context.Context, req VerifyRequest) (*IdentityPrincipal, error) {
	var norm string
	var err error
	if a.idType == model.IdentityPhone {
		norm, err = identity.NormalizePhone(req.Identity)
	} else {
		norm, err = identity.NormalizeEmail(req.Identity)
	}
	if err != nil {
		return nil, errcode.New(errcode.BadRequest, "身份格式错误")
	}
	password := req.Credential["password"]
	if password == "" {
		return nil, errcode.New(errcode.BadRequest, "缺少 password")
	}

	idKey := "uac:rl:pwd:fail:id:" + norm
	if blocked, err := a.failCountAtLeast(ctx, idKey, pwdFailLimit); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "限流失败", err)
	} else if blocked {
		return nil, errcode.New(errcode.RateLimited, "尝试次数过多，请稍后重试")
	}
	ipKey := ""
	if req.IP != "" {
		ipKey = "uac:rl:pwd:fail:ip:" + req.IP
		if blocked, err := a.failCountAtLeast(ctx, ipKey, 30); err != nil {
			return nil, errcode.Wrap(errcode.Internal, "限流失败", err)
		} else if blocked {
			return nil, errcode.New(errcode.RateLimited, "尝试次数过多，请稍后重试")
		}
	}

	fail := func() {
		_, _, _ = a.redis.Allow(ctx, idKey, pwdFailLimit, pwdFailWindow)
		if ipKey != "" {
			_, _, _ = a.redis.Allow(ctx, ipKey, 30, pwdFailWindow)
		}
	}

	idn, err := a.idRepo.FindByUnique(ctx, req.TenantID, a.idType, "", norm)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询身份失败", err)
	}
	if idn == nil {
		fail()
		return nil, errcode.New(errcode.InvalidCred, "账号或密码错误")
	}

	cred, err := a.credRepo.FindByUserID(ctx, idn.UserID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询凭证失败", err)
	}
	if cred == nil || cred.PasswordHash == "" {
		fail()
		return nil, errcode.New(errcode.InvalidCred, "账号或密码错误")
	}
	passOK, err := crypto.VerifyPassword(cred.PasswordHash, password)
	if err != nil || !passOK {
		fail()
		return nil, errcode.New(errcode.InvalidCred, "账号或密码错误")
	}

	_ = a.redis.Raw().Del(ctx, idKey).Err()

	return &IdentityPrincipal{
		Type:       a.idType,
		Identifier: norm,
		Verified:   idn.Verified,
		Profile: map[string]interface{}{
			"user_id": idn.UserID,
		},
	}, nil
}

func (a *PasswordAuth) failCountAtLeast(ctx context.Context, key string, limit int) (bool, error) {
	val, err := a.redis.Raw().Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	n, _ := strconv.Atoi(val)
	return n >= limit, nil
}
