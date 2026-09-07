package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/vertify/license-platform/internal/argon2id"
	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/store"
)

// ===== 管理员认证 =====

var (
	ErrBadCredentials = errors.New("bad credentials")
	ErrAccountLocked  = errors.New("account locked")
	ErrMFARequired    = errors.New("mfa required")
	ErrMFABad         = errors.New("mfa code invalid")
	ErrSessionGone    = errors.New("session expired")
	ErrCSRF           = errors.New("csrf token mismatch")
)

type LoginResult struct {
	SessionToken string // 明文，仅经 Set-Cookie 下发一次
	CSRFToken    string
	MFARequired  bool
	Admin        *store.Admin
}

// pendingTOTP 暂存 MFA 设置流程中的密钥（验证通过前不入库）。
// 单实例内存即可：MFA 设置是一次短交互，丢失重扫即可。

// AdminLogin 管理员登录：Argon2id 校验 → 锁定检查 → 可选 TOTP → 创建会话。
// 会话凭据为 256bit 随机 token，cookie 只出明文一次，库存 SHA-256。
func (s *Services) AdminLogin(ctx context.Context, username, password, totp, ip, ua, requestID string) (*LoginResult, error) {
	admin, err := s.Store.Q().GetAdminByUsername(ctx, username)
	if err == store.ErrNoRows {
		// 恒定时间路径：即使用户不存在也执行一次哈希，缓解用户名枚举
		_, _ = argon2id.Hash(password, argon2id.DefaultParams())
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if admin.Status != "active" {
		return nil, ErrBadCredentials
	}
	if admin.LockedUntil != nil && admin.LockedUntil.After(time.Now()) {
		s.Risk.Record(ctx, "admin_login_locked", "high", admin.Username, ip)
		return nil, ErrAccountLocked
	}
	ok, err := argon2id.Verify(password, admin.PasswordHash)
	if err != nil || !ok {
		locked, _ := s.Store.Q().OnLoginFailed(ctx, admin.ID)
		s.Risk.Record(ctx, "admin_login_failed", "medium", admin.Username, map[string]any{"ip": ip, "locked": locked})
		return nil, ErrBadCredentials
	}
	mfaPassed := true
	if admin.MFAEnabled {
		if totp == "" {
			return nil, ErrMFARequired
		}
		if !crypto.VerifyTOTP(*admin.TOTPSecret, totp, time.Now().Unix()) {
			locked, _ := s.Store.Q().OnLoginFailed(ctx, admin.ID)
			s.Risk.Record(ctx, "admin_mfa_failed", "high", admin.Username, map[string]any{"ip": ip, "locked": locked})
			return nil, ErrMFABad
		}
		mfaPassed = true
	}
	if err := s.Store.Q().OnLoginSuccess(ctx, admin.ID); err != nil {
		return nil, err
	}
	token, err := crypto.RandomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := crypto.RandomToken(24)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(token))
	sess := &store.AdminSession{
		ID:        uuid.NewString(),
		AdminID:   admin.ID,
		TokenHash: hex.EncodeToString(sum[:]),
		CSRFToken: csrf,
		MFAPassed: mfaPassed,
		ExpiresAt: time.Now().Add(s.Cfg.AdminSessionTTL),
	}
	if err := s.Store.Q().CreateSession(ctx, sess, ip, ua); err != nil {
		return nil, err
	}
	_ = s.Store.Q().InsertAudit(ctx, &store.AuditLog{
		AdminID: &admin.ID, AdminUsername: &admin.Username, Action: "auth.login",
		IP: &ip, RequestID: &requestID,
	})
	return &LoginResult{SessionToken: token, CSRFToken: csrf, Admin: admin}, nil
}

// AdminSession 认证后的会话上下文（middleware 附加到请求）。
type AdminContext struct {
	Session *store.AdminSession
	Admin   *store.Admin
}

// ResolveSession 校验会话 token（SHA-256 查找）。
func (s *Services) ResolveSession(ctx context.Context, token string) (*AdminContext, error) {
	sum := sha256.Sum256([]byte(token))
	sess, err := s.Store.Q().GetSessionByTokenHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, ErrSessionGone
	}
	admin, err := s.Store.Q().GetAdmin(ctx, sess.AdminID)
	if err != nil || admin.Status != "active" {
		return nil, ErrSessionGone
	}
	return &AdminContext{Session: sess, Admin: admin}, nil
}

// CheckCSRF 校验写请求 CSRF 头。
func (s *Services) CheckCSRF(ac *AdminContext, header string) error {
	if header == "" || header != ac.Session.CSRFToken {
		return ErrCSRF
	}
	return nil
}

// Audit 记录管理操作审计（变更前后快照）。
func (s *Services) Audit(ctx context.Context, ac *AdminContext, action, targetType, targetID string, before, after, detail any, ip, requestID string) {
	entry := &store.AuditLog{
		AdminID: &ac.Admin.ID, AdminUsername: &ac.Admin.Username,
		Action: action, TargetType: ptr(targetType), TargetID: ptr(targetID),
		BeforeState: mustJSON(before), AfterState: mustJSON(after),
		Detail: mustJSON(detail), IP: ptr(ip), RequestID: ptr(requestID),
	}
	if err := s.Store.Q().InsertAudit(ctx, entry); err != nil {
		slog.Warn("audit insert failed", "err", err)
	}
}

func ptr[T any](v T) *T { return &v }

// hashPassword 统一使用当前默认 Argon2id 参数。
func hashPassword(password string) (string, error) {
	return argon2id.Hash(password, argon2id.DefaultParams())
}

// BootstrapAdmin 创建第一个管理员（仅迁移后空表时由 server 启动调用）。
func (s *Services) BootstrapAdmin(ctx context.Context, username, password, totpSecret string) (*store.Admin, error) {
	if len(password) < 12 {
		return nil, errors.New("initial admin password must be >= 12 chars")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	a := &store.Admin{
		Username:           username,
		PasswordHash:       hash,
		DisplayName:        "System Administrator",
		Role:               string(domain.AdminSuperAdmin),
		MustChangePassword: true,
	}
	if totpSecret != "" {
		norm, err := crypto.NormalizeTOTPSecret(totpSecret)
		if err != nil {
			return nil, err
		}
		a.TOTPSecret = &norm
		a.MFAEnabled = true
	}
	return s.Store.Q().CreateAdmin(ctx, a)
}

// ===== MFA（TOTP）管理 =====

// MFASetup 生成新 TOTP 密钥（暂存内存，验证通过后才落库启用）。
func (s *Services) MFASetup(ctx context.Context, ac *AdminContext) (string, error) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		return "", err
	}
	if err := s.Cache.SetPendingTOTP(ctx, ac.Admin.ID, secret, 10*time.Minute); err != nil {
		return "", err
	}
	return secret, nil
}

func (s *Services) MFAUri(secret, username string) string {
	return crypto.TOTPProvisioningURI(secret, username, "Vertify")
}

// MFAEnable 用当前动态码确认并启用 MFA。
func (s *Services) MFAEnable(ctx context.Context, ac *AdminContext, code string) error {
	secret, err := s.Cache.ConsumePendingTOTP(ctx, ac.Admin.ID)
	if err != nil {
		return err
	}
	step := time.Now().Unix() / 30
	if !crypto.VerifyTOTP(secret, code, time.Now().Unix()) {
		return ErrMFABad
	}
	used, err := s.Cache.ConsumeTOTPWindow(ctx, ac.Admin.ID, step, 90*time.Second)
	if err != nil {
		return err
	}
	if !used {
		return ErrMFABad
	}
	if err := s.Store.Q().SetAdminMFA(ctx, ac.Admin.ID, &secret, true); err != nil {
		return err
	}
	if err := s.Store.Q().RevokeAllSessions(ctx, ac.Admin.ID); err != nil {
		return err
	}
	if err := s.Store.Q().RevokeAllSessions(ctx, ac.Admin.ID); err != nil {
		return err
	}
	s.Audit(ctx, ac, "auth.mfa_enable", "admin", ac.Admin.ID, nil, nil, nil, "", "")
	return nil
}

// MFADisable 关闭 MFA（需口令二次确认）。
func (s *Services) MFADisable(ctx context.Context, ac *AdminContext, password string) error {
	ok, err := argon2id.Verify(password, ac.Admin.PasswordHash)
	if err != nil || !ok {
		return ErrBadCredentials
	}
	if err := s.Store.Q().SetAdminMFA(ctx, ac.Admin.ID, nil, false); err != nil {
		return err
	}
	if err := s.Store.Q().RevokeAllSessions(ctx, ac.Admin.ID); err != nil {
		return err
	}
	s.Audit(ctx, ac, "auth.mfa_disable", "admin", ac.Admin.ID, nil, nil, nil, "", "")
	return nil
}

// AdminChangePassword 修改口令：验证旧口令 → Argon2id 新哈希 → 吊销其他会话。
// 返回为本浏览器签发的新会话凭据（不强制当前浏览器重登）。
func (s *Services) AdminChangePassword(ctx context.Context, ac *AdminContext, oldPw, newPw string) (sessionToken, csrf string, err error) {
	if len(newPw) < 12 {
		return "", "", errors.New("password too short")
	}
	ok, err := argon2id.Verify(oldPw, ac.Admin.PasswordHash)
	if err != nil || !ok {
		return "", "", ErrBadCredentials
	}
	hash, err := hashPassword(newPw)
	if err != nil {
		return "", "", err
	}
	if err := s.Store.Q().SetAdminPassword(ctx, ac.Admin.ID, hash, false); err != nil {
		return "", "", err
	}
	// 其他会话全部吊销（含本次之前的）
	if err := s.Store.Q().RevokeAllSessions(ctx, ac.Admin.ID); err != nil {
		return "", "", err
	}
	// 为当前浏览器签发新会话
	token, err := crypto.RandomToken(32)
	if err != nil {
		return "", "", err
	}
	csrfTok, err := crypto.RandomToken(24)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(token))
	sess := &store.AdminSession{
		ID:        uuid.NewString(),
		AdminID:   ac.Admin.ID,
		TokenHash: hex.EncodeToString(sum[:]),
		CSRFToken: csrfTok,
		MFAPassed: true,
		ExpiresAt: time.Now().Add(s.Cfg.AdminSessionTTL),
	}
	if err := s.Store.Q().CreateSession(ctx, sess, "", ""); err != nil {
		return "", "", err
	}
	s.Audit(ctx, ac, "auth.password_change", "admin", ac.Admin.ID, nil, nil, nil, "", "")
	return token, csrfTok, nil
}
