// 终端用户账号体系：注册/登录/绑卡续期/改密/找回/机器绑定。
// 账号制与卡密激活制并存：同一张卡只能被其中一种方式消耗。
package service

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/vertify/license-platform/internal/argon2id"
	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/store"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)

const endUserTokenTTL = 10 * time.Minute

// GetProductIDByCode 产品代码 → ID。
func (s *Services) GetProductIDByCode(ctx context.Context, code string) (string, error) {
	p, err := s.Store.Q().GetProductByCode(ctx, strings.ToUpper(strings.TrimSpace(code)))
	if err != nil {
		return "", domain.ErrProductRetired
	}
	if p.Status != "active" {
		return "", domain.ErrProductRetired
	}
	return p.ID, nil
}

// hashPasswordEnd 终端用户口令（参数低于管理员，量大换性能）。
func hashPasswordEnd(password string) (string, error) {
	return argon2id.Hash(password, argon2id.Params{MemoryKiB: 8192, Time: 2, Threads: 1, KeyLen: 32, SaltLen: 16})
}

func (s *Services) logUser(ctx context.Context, userID *string, username, kind string, productID, ip *string, detail map[string]any) {
	_ = s.Store.Q().InsertEndUserLog(ctx, userID, username, kind, productID, ip, detail)
}

// ===== 注册 =====

func (s *Services) UserRegister(ctx context.Context, productCode, username, password, securityCode, ip, requestID string) error {
	if !usernameRe.MatchString(username) {
		return domain.ErrBadUsername
	}
	if len(password) < 6 {
		return errors.New("password too short")
	}
	if len(securityCode) < 4 {
		return errors.New("security code too short")
	}
	productID, err := s.GetProductIDByCode(ctx, productCode)
	if err != nil {
		return err
	}
	if _, err := s.Store.Q().GetEndUserByName(ctx, productID, username); err == nil {
		return domain.ErrUserExists
	} else if err != store.ErrNoRows {
		return err
	}
	pwHash, err := hashPasswordEnd(password)
	if err != nil {
		return err
	}
	secHash, err := hashPasswordEnd(securityCode)
	if err != nil {
		return err
	}
	_, err = s.Store.Q().CreateEndUser(ctx, &store.EndUser{
		ProductID:    productID,
		Username:     username,
		PasswordHash: pwHash,
		SecurityHash: secHash,
		// expires_at 默认 now()：注册后需绑卡才有有效期
		RegIP: strPtr(ip),
	})
	if err != nil {
		if err == store.ErrNoRows || IsUniqueErr(err) {
			return domain.ErrUserExists
		}
		return err
	}
	u, err := s.Store.Q().GetEndUserByName(ctx, productID, username)
	if err != nil {
		return err
	}
	s.logUser(ctx, &u.ID, username, "register", &productID, strPtr(ip), nil)
	return nil
}

// IsUniqueErr 包装唯一约束判断（避免 service 直接依赖 pgconn）。
func IsUniqueErr(err error) bool { return store.IsUnique(err) }

// ===== 登录 =====

type UserLoginResult struct {
	Token     string       `json:"token"`
	ExpiresAt int64        `json:"expires_at"`
	Expired   bool         `json:"expired"`
	Status    string       `json:"status"`
	Message   string       `json:"message,omitempty"`
	Version   *VersionInfo `json:"version,omitempty"`
}

type VersionInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	ForceUpdate bool   `json:"force_update"`
}

// UserLogin 登录：口令校验 → 机器绑定（首登绑定 / 换机拒绝）→ 签发用户令牌。
// 过期账号允许登录（可绑卡续期），但响应携带 expired=true。
func (s *Services) UserLogin(ctx context.Context, productCode, username, password string, components []string, ip, requestID string) (*UserLoginResult, error) {
	productID, err := s.GetProductIDByCode(ctx, productCode)
	if err != nil {
		return nil, ErrBadCredentials
	}
	u, err := s.Store.Q().GetEndUserByName(ctx, productID, username)
	if errors.Is(err, store.ErrNoRows) {
		_, _ = hashPasswordEnd(password) // 恒定路径防用户名枚举
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	ipP := strPtr(ip)
	if u.Status != "active" {
		s.logUser(ctx, &u.ID, username, "login_failed", &productID, ipP, map[string]any{"reason": "disabled"})
		return nil, domain.ErrUserDisabled
	}
	ok, err := argon2id.Verify(password, u.PasswordHash)
	if err != nil || !ok {
		s.logUser(ctx, &u.ID, username, "login_failed", &productID, ipP, nil)
		return nil, ErrBadCredentials
	}

	// 机器绑定
	fpHash := s.FingerprintHash(components)
	if u.MachineHash == nil {
		if err := s.Store.Q().BindEndUserMachine(ctx, u.ID, fpHash); err != nil {
			return nil, err
		}
	} else if *u.MachineHash != fpHash {
		s.logUser(ctx, &u.ID, username, "login_machine_rejected", &productID, ipP, nil)
		return nil, domain.ErrMachineBound
	}

	// 更新登录元数据
	_ = s.Store.Q().TouchEndUserLogin(ctx, u.ID, ip)

	res := &UserLoginResult{}
	if u.ExpiresAt.Before(time.Now()) {
		res.Expired = true
		res.Status = "expired"
		res.Message = "账号已到期，请绑定卡密续期"
	} else {
		res.Status = "active"
	}
	res.ExpiresAt = u.ExpiresAt.Unix()

	// 签发用户令牌（绑卡/改密用，10 分钟）
	claims := crypto.LeaseClaims{
		Typ:    crypto.TokenTypeUser,
		JTI:    mustRandom(),
		Lic:    u.ID, // 复用字段存用户 ID
		Prod:   productCode,
		Iss:    time.Now().Unix(),
		Exp:    time.Now().Add(endUserTokenTTL).Unix(),
		Status: string(domain.LicenseActive),
	}
	token, err := crypto.MintToken(s.Keys, claims)
	if err != nil {
		return nil, err
	}
	res.Token = token

	// 顺带下发公告与最新版本（对应参考系统的软件留言/取版本）
	if msg, merr := s.Store.Q().LatestEnabledMessage(ctx, productID); merr == nil && msg != "" {
		res.Message = msg
	}
	if v, verr := s.Store.Q().LatestProductVersion(ctx, productID); verr == nil {
		res.Version = &VersionInfo{Version: v.Version, DownloadURL: v.DownloadURL, ForceUpdate: v.ForceUpdate}
	}
	s.logUser(ctx, &u.ID, username, "login", &productID, ipP, nil)
	return res, nil
}

// parseUserToken 校验用户令牌并返回用户 ID。
func (s *Services) parseUserToken(ctx context.Context, token string) (string, *store.EndUser, error) {
	claims, err := crypto.VerifyTokenWithType(token, "user", time.Now(), s.Keys)
	if err != nil {
		return "", nil, domain.ErrBadSignature
	}
	u, err := s.Store.Q().GetEndUser(ctx, claims.Lic)
	if err != nil {
		return "", nil, domain.ErrBadSignature
	}
	if u.Status != "active" {
		return "", nil, domain.ErrUserDisabled
	}
	return u.ID, u, nil
}

// ===== 绑卡续期 =====

func (s *Services) UserBindCard(ctx context.Context, token, cardInput, ip, requestID string) (*time.Time, error) {
	userID, user, err := s.parseUserToken(ctx, token)
	if err != nil {
		return nil, err
	}
	normalized, err := crypto.NormalizeCard(cardInput)
	if err != nil {
		return nil, domain.ErrCardInvalidFormat
	}
	lookup := s.CardLookup(normalized)
	var newExp *time.Time
	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		u, err := q.GetEndUser(ctx, userID)
		if err != nil {
			return err
		}
		card, err := q.GetCardByLookup(ctx, lookup, true)
		if errors.Is(err, store.ErrNoRows) {
			return domain.ErrCardNotFound
		}
		if err != nil {
			return err
		}
		if card.ProductID != u.ProductID {
			return domain.ErrCardNotUsable
		}
		if card.Kind != "license" {
			return domain.ErrCardNotUsable
		}
		if card.Status != "unused" || card.LicenseID != nil || card.UsedByUser != nil {
			return mapCardErr(card.Status)
		}
		plan, err := q.GetPlan(ctx, card.PlanID)
		if err != nil {
			return err
		}
		if plan.DurationDays <= 0 {
			return domain.ErrCardNotUsable
		}
		if err := q.MarkCardUsedByUser(ctx, card.ID, userID); err != nil {
			return domain.ErrCardNotUsable
		}
		newExp, err = q.ExtendEndUser(ctx, userID, plan.DurationDays)
		if err != nil {
			return err
		}
		return q.InsertEndUserLog(ctx, &userID, user.Username, "bind_card", &user.ProductID, strPtr(ip),
			map[string]any{"card_prefix": card.Prefix, "days": plan.DurationDays, "new_expiry": newExp})
	})
	if err != nil {
		return nil, err
	}
	return newExp, nil
}

// ===== 改密 / 找回 =====

func (s *Services) UserChangePassword(ctx context.Context, token, oldPw, newPw string) error {
	userID, user, err := s.parseUserToken(ctx, token)
	if err != nil {
		return err
	}
	if len(newPw) < 6 {
		return errors.New("password too short")
	}
	if ok, _ := argon2id.Verify(oldPw, user.PasswordHash); !ok {
		return ErrBadCredentials
	}
	hash, err := hashPasswordEnd(newPw)
	if err != nil {
		return err
	}
	if err := s.Store.Q().SetEndUserPassword(ctx, userID, hash); err != nil {
		return err
	}
	s.logUser(ctx, &userID, user.Username, "change_pw", &user.ProductID, nil, nil)
	return nil
}

func (s *Services) UserRecover(ctx context.Context, productCode, username, securityCode, newPassword, ip string) error {
	if len(newPassword) < 6 {
		return errors.New("password too short")
	}
	productID, err := s.GetProductIDByCode(ctx, productCode)
	if err != nil {
		return ErrBadCredentials
	}
	u, err := s.Store.Q().GetEndUserByName(ctx, productID, username)
	if errors.Is(err, store.ErrNoRows) {
		_, _ = hashPasswordEnd(securityCode)
		return ErrBadCredentials
	}
	if err != nil {
		return err
	}
	if ok, _ := argon2id.Verify(securityCode, u.SecurityHash); !ok {
		s.logUser(ctx, &u.ID, username, "recover", &productID, strPtr(ip), map[string]any{"ok": false})
		return domain.ErrBadSecurityCode
	}
	hash, err := hashPasswordEnd(newPassword)
	if err != nil {
		return err
	}
	if err := s.Store.Q().SetEndUserPassword(ctx, u.ID, hash); err != nil {
		return err
	}
	s.logUser(ctx, &u.ID, username, "recover", &productID, strPtr(ip), map[string]any{"ok": true})
	return nil
}
