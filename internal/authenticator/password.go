package authenticator

import (
	"context"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/crypto"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/identity"
	"github.com/davveo/unified-account-center/internal/repository"
)

type PasswordAuth struct {
	method   string
	idType   string
	idRepo   repository.IdentityRepo
	credRepo repository.CredentialRepo
}

func NewPhonePassword(idRepo repository.IdentityRepo, credRepo repository.CredentialRepo) *PasswordAuth {
	return &PasswordAuth{
		method:   model.MethodPhonePassword,
		idType:   model.IdentityPhone,
		idRepo:   idRepo,
		credRepo: credRepo,
	}
}

func NewEmailPassword(idRepo repository.IdentityRepo, credRepo repository.CredentialRepo) *PasswordAuth {
	return &PasswordAuth{
		method:   model.MethodEmailPassword,
		idType:   model.IdentityEmail,
		idRepo:   idRepo,
		credRepo: credRepo,
	}
}

func (a *PasswordAuth) Method() string { return a.method }

func (a *PasswordAuth) Challenge(ctx context.Context, req ChallengeRequest) (*ChallengeResult, error) {
	// 密码登录无需发码；可选图形验证码预留。
	return &ChallengeResult{
		ChallengeID:  "",
		ExpireIn:     0,
		ResendAfter:  0,
		MaskedTarget: "",
	}, nil
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

	idn, err := a.idRepo.FindByUnique(ctx, req.TenantID, a.idType, "", norm)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询身份失败", err)
	}
	if idn == nil {
		return nil, errcode.New(errcode.InvalidCred, "账号或密码错误")
	}

	cred, err := a.credRepo.FindByUserID(ctx, idn.UserID)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "查询凭证失败", err)
	}
	if cred == nil || cred.PasswordHash == "" {
		return nil, errcode.New(errcode.InvalidCred, "账号或密码错误")
	}
	ok, err := crypto.VerifyPassword(cred.PasswordHash, password)
	if err != nil || !ok {
		return nil, errcode.New(errcode.InvalidCred, "账号或密码错误")
	}

	return &IdentityPrincipal{
		Type:       a.idType,
		Identifier: norm,
		Verified:   idn.Verified,
		Profile: map[string]interface{}{
			"user_id": idn.UserID,
		},
	}, nil
}
