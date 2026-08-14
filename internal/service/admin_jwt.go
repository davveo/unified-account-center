package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/jwtutil"
)

type JWTKeysView struct {
	Alg                    string `json:"alg"`
	CurrentKid             string `json:"current_kid"`
	PreviousKid            string `json:"previous_kid,omitempty"`
	DualKey                bool   `json:"dual_key"`
	PrivateKeyPath         string `json:"private_key_path,omitempty"`
	PublicKeyPath          string `json:"public_key_path,omitempty"`
	PreviousPrivateKeyPath string `json:"previous_private_key_path,omitempty"`
	PreviousPublicKeyPath  string `json:"previous_public_key_path,omitempty"`
	Note                   string `json:"note,omitempty"`
}

type RotateJWTKeysRequest struct {
	Kid string `json:"kid"` // 可选；空则自动生成 rsa-<unix>
}

func (s *AdminService) GetJWTKeys(_ context.Context) (*JWTKeysView, error) {
	if s.jwt == nil {
		return nil, errcode.New(errcode.Internal, "JWT 未配置")
	}
	st := s.jwt.Status()
	view := &JWTKeysView{
		Alg:         st.Alg,
		CurrentKid:  st.CurrentKid,
		PreviousKid: st.PreviousKid,
		DualKey:     st.DualKey,
		Note:        "RS256 支持双钥滚动：新钥签名，旧钥只验不签；Access 过期后可下线旧钥",
	}
	if s.cfg != nil {
		view.PrivateKeyPath = s.cfg.JWT.PrivateKeyPath
		view.PublicKeyPath = s.cfg.JWT.PublicKeyPath
		view.PreviousPrivateKeyPath = s.previousPrivatePath()
		view.PreviousPublicKeyPath = s.previousPublicPath()
	}
	if st.Alg != "RS256" {
		view.Note = "当前为 HS256，双钥滚动仅适用于 RS256"
	}
	return view, nil
}

func (s *AdminService) RotateJWTKeys(ctx context.Context, req RotateJWTKeysRequest, actor string) (*JWTKeysView, error) {
	if s.jwt == nil {
		return nil, errcode.New(errcode.Internal, "JWT 未配置")
	}
	if s.jwt.Alg() != "RS256" {
		return nil, errcode.New(errcode.BadRequest, "仅 RS256 支持 kid 双钥滚动")
	}
	if s.cfg == nil || s.cfg.JWT.PrivateKeyPath == "" {
		return nil, errcode.New(errcode.BadRequest, "未配置 jwt.private_key_path，无法落盘轮换")
	}

	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errcode.Wrap(errcode.Internal, "生成 RSA 密钥失败", err)
	}
	newKid := req.Kid
	if newKid == "" {
		newKid = fmt.Sprintf("rsa-%d", time.Now().Unix())
	}
	oldKid := s.jwt.Kid()
	if err := s.jwt.RotateRSA(newKey, newKid); err != nil {
		return nil, errcode.Wrap(errcode.BadRequest, "轮换失败", err)
	}

	currPriv, prevPriv, currKid, prevKid := s.jwt.SnapshotKeys()
	if err := jwtutil.WriteRSAKeyPair(currPriv, s.cfg.JWT.PrivateKeyPath, s.cfg.JWT.PublicKeyPath); err != nil {
		return nil, errcode.Wrap(errcode.Internal, "写入当前密钥失败", err)
	}
	_ = jwtutil.WriteKidFile(s.cfg.JWT.PrivateKeyPath, currKid)

	prevPrivPath := s.previousPrivatePath()
	prevPubPath := s.previousPublicPath()
	if prevPriv != nil {
		if err := jwtutil.WriteRSAKeyPair(prevPriv, prevPrivPath, prevPubPath); err != nil {
			return nil, errcode.Wrap(errcode.Internal, "写入旧密钥失败", err)
		}
		_ = jwtutil.WriteKidFile(prevPrivPath, prevKid)
		if prevPubPath != "" {
			_ = jwtutil.WriteKidFile(prevPubPath, prevKid)
		}
	}

	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_rotate_jwt_keys", Success: true,
		Detail:    fmt.Sprintf("from_kid=%s to_kid=%s previous_kid=%s", oldKid, currKid, prevKid),
		CreatedAt: time.Now(),
	})
	return s.GetJWTKeys(ctx)
}

func (s *AdminService) RetireJWTPrevious(ctx context.Context, actor string) (*JWTKeysView, error) {
	if s.jwt == nil {
		return nil, errcode.New(errcode.Internal, "JWT 未配置")
	}
	if s.jwt.Alg() != "RS256" {
		return nil, errcode.New(errcode.BadRequest, "仅 RS256 支持双钥滚动")
	}
	prevKid := s.jwt.PreviousKid()
	if prevKid == "" {
		return nil, errcode.New(errcode.BadRequest, "当前没有旧钥可下线")
	}
	s.jwt.ClearPreviousRSA()

	prevPrivPath := s.previousPrivatePath()
	prevPubPath := s.previousPublicPath()
	_ = os.Remove(prevPrivPath)
	_ = os.Remove(prevPubPath)
	jwtutil.RemoveKidFile(prevPrivPath)
	jwtutil.RemoveKidFile(prevPubPath)

	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_retire_jwt_previous", Success: true,
		Detail: "previous_kid=" + prevKid, CreatedAt: time.Now(),
	})
	return s.GetJWTKeys(ctx)
}

func (s *AdminService) previousPrivatePath() string {
	if s.cfg == nil {
		return ""
	}
	if s.cfg.JWT.PreviousPrivateKeyPath != "" {
		return s.cfg.JWT.PreviousPrivateKeyPath
	}
	return jwtutil.SiblingPrevPath(s.cfg.JWT.PrivateKeyPath)
}

func (s *AdminService) previousPublicPath() string {
	if s.cfg == nil {
		return ""
	}
	if s.cfg.JWT.PreviousPublicKeyPath != "" {
		return s.cfg.JWT.PreviousPublicKeyPath
	}
	return jwtutil.SiblingPrevPath(s.cfg.JWT.PublicKeyPath)
}
