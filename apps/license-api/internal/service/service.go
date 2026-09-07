// Package service 实现许可业务：激活、机器码绑定、心跳租约、兑换、吊销传播。
// 全部授权决策在服务端；本包是唯一事实来源。
package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf" //nolint:staticcheck
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vertify/license-platform/internal/cache"
	"github.com/vertify/license-platform/internal/config"
	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/store"
)

// unmarshalStrict 严格解析：拒绝未知字段，收窄协议面。
func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func mustRandom() string {
	s, _ := crypto.RandomToken(12)
	return s
}

// Services 聚合全部业务依赖。
type Services struct {
	Cfg   *config.Config
	Keys  crypto.Signer
	Kex   []*crypto.KexKeyPair
	Store *store.Store
	Cache *cache.Cache
	Risk  *Risk

	cardHMACKey   []byte
	cardEncKeys   map[string][]byte
	cardEncActive string
	fpSaltKey     []byte

	mu          sync.RWMutex
	pendingTOTP map[string]string
}

func New(cfg *config.Config, keys crypto.Signer, kex []*crypto.KexKeyPair, st *store.Store, c *cache.Cache) (*Services, error) {
	s := &Services{
		Cfg: cfg, Keys: keys, Kex: kex, Store: st, Cache: c,
		Risk:        &Risk{Store: st, Cache: c},
		pendingTOTP: make(map[string]string),
	}
	s.cardHMACKey = cfg.CardHMACKey
	s.cardEncKeys = cfg.CardEncKeys
	s.cardEncActive = cfg.CardEncActive
	// 从卡密 HMAC 主密钥派生独立的指纹盐密钥（域分离）
	r, err := hkdf.Key(sha256.New, cfg.CardHMACKey, []byte("vertify"), "fingerprint-salt-v1", 32)
	if err != nil {
		return nil, err
	}
	s.fpSaltKey = r
	return s, nil
}

func (s *Services) EncryptCardSecret(cardID, batchID, productID, normalized string) ([]byte, []byte, string, error) {
	key := s.cardEncKeys[s.cardEncActive]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, "", err
	}
	aad := []byte("vertify-card-secret-v1|" + productID)
	return gcm.Seal(nil, nonce, []byte(normalized), aad), nonce, s.cardEncActive, nil
}

func (s *Services) DecryptCardSecret(cardID, batchID, productID string, ct, nonce []byte, kid string) (string, error) {
	key, ok := s.cardEncKeys[kid]
	if !ok {
		return "", fmt.Errorf("unknown card key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, nonce, ct, []byte("vertify-card-secret-v1|"+productID))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// CardLookup 计算卡密检索哈希。
func (s *Services) CardLookup(normalized string) string {
	return crypto.CardHMAC(s.cardHMACKey, normalized)
}

// FingerprintHash 服务端盐化指纹摘要：
// 客户端只上传各分量的 SHA-256 摘要，服务器持盐合并——数据库不含原始硬件序列号。
func (s *Services) FingerprintHash(componentDigests []string) string {
	h := sha256.New()
	for _, d := range componentDigests {
		h.Write([]byte(d))
		h.Write([]byte{0x00})
	}
	mac := h.Sum(nil)
	macced := sha256.Sum256(append(append([]byte("vertify-fp-v1"), mac...), s.fpSaltKey...))
	return base64.RawURLEncoding.EncodeToString(macced[:])
}

// b64PubRe：ed25519 公钥 43 字符 / P-256 非压缩点 87 字符（base64url）。
var b64PubRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}(?:[A-Za-z0-9_-]{44})?$`)

var digestRe = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)

func validDevicePub(pub string) bool { return b64PubRe.MatchString(pub) }

func validComponents(components []string) bool {
	if len(components) == 0 || len(components) > 16 {
		return false
	}
	seen := make(map[string]struct{}, len(components))
	for _, d := range components {
		d = strings.TrimSpace(d)
		if !digestRe.MatchString(d) {
			return false
		}
		key := strings.ToLower(d)
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

var versionRe = regexp.MustCompile(`^\d+(?:\.\d+)*$`)

// CompareVersion 比较点分版本号：-1/0/1；非法版本按最低优先级处理。
func CompareVersion(a, b string) int {
	if !versionRe.MatchString(a) || !versionRe.MatchString(b) {
		if !versionRe.MatchString(a) && versionRe.MatchString(b) {
			return -1
		}
		if versionRe.MatchString(a) && !versionRe.MatchString(b) {
			return 1
		}
		return 0
	}
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, bi := 0, 0
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

// ActivatePayload 激活信封解密后的载荷。
type ActivatePayload struct {
	Card          string            `json:"card"`
	Components    []string          `json:"components"` // 各指纹分量摘要
	DevicePub     string            `json:"device_pub"`
	PubKty        string            `json:"pub_kty,omitempty"` // ed25519 | p256
	TrustLevel    string            `json:"trust_level"`
	ClientVersion string            `json:"client_version"`
	Extra         map[string]string `json:"extra,omitempty"`
}

type ActivationResult struct {
	LicenseID     string             `json:"license_id"`
	ProductCode   string             `json:"product_code"`
	DeviceID      string             `json:"device_id"`
	Lease         string             `json:"lease"`
	LeaseClaims   crypto.LeaseClaims `json:"-"`
	PlanCode      string             `json:"plan_code"`
	Features      []string           `json:"features"`
	HeartbeatSec  int                `json:"heartbeat_interval_seconds"`
	LeaseTTL      int                `json:"lease_ttl_seconds"`
	OfflineGrace  int                `json:"offline_grace_seconds"`
	ConcurrentLim int                `json:"-"`
	LicenseExpiry *time.Time         `json:"license_expiry"`
	Reactivated   bool               `json:"reactivated"`
}

// Activate 执行激活。envelopeJSON 为信封密文，deviceSig 为设备签名头字段。
func (s *Services) Activate(ctx context.Context, envelopeJSON []byte, deviceSig *DeviceSignature, ip, requestID string) (*ActivationResult, error) {
	// 1. 信封解密（AAD 绑定 purpose 防跨接口重放密文）
	pt, err := crypto.OpenEnvelope(envelopeJSON, "", s.Kex, crypto.AADContext("activate"))
	if err != nil {
		return nil, err
	}
	var payload ActivatePayload
	if err := unmarshalStrict(pt, &payload); err != nil {
		return nil, fmtErrBadCard
	}
	if payload.Card == "" || !validDevicePub(payload.DevicePub) || !validComponents(payload.Components) {
		return nil, domain.ErrCardInvalidFormat
	}
	if payload.TrustLevel != "tpm" && payload.TrustLevel != "software" {
		payload.TrustLevel = "software"
	}
	if payload.PubKty != "p256" {
		payload.PubKty = "ed25519"
	}

	// 2. 设备签名验证（对信封原文签名 = PoP + 完整性绑定）
	if deviceSig == nil {
		return nil, domain.ErrBadSignature
	}
	msg := deviceSig.Message("POST", "/v1/activate", envelopeJSON)
	if !deviceSig.VerifyPub(payload.DevicePub, payload.PubKty, msg) {
		return nil, domain.ErrBadSignature
	}

	// 3.5 防重放：激活签名必须先消费 nonce/序列号，避免同一密文重复提交。
	if err := s.checkActivationReplay(ctx, deviceSig, payload.DevicePub, ip); err != nil {
		return nil, err
	}

	// 4. 卡密规范化与检索
	normalized, err := crypto.NormalizeCard(payload.Card)
	if err != nil {
		return nil, domain.ErrCardInvalidFormat
	}
	lookup := s.CardLookup(normalized)
	fpHash := s.FingerprintHash(payload.Components)

	// 封禁执行（泄露卡密应急处置链路）：卡密前缀 / 设备公钥
	if banned, _ := s.Store.Q().IsBanned(ctx, "card_prefix", crypto.CardPrefix(normalized)); banned {
		return nil, domain.ErrBanned
	}
	if banned, _ := s.Store.Q().IsBanned(ctx, "device", payload.DevicePub); banned {
		return nil, domain.ErrBanned
	}

	now := time.Now()
	var result *ActivationResult

	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		card, err := q.GetCardByLookup(ctx, lookup, true)
		if err == store.ErrNoRows {
			return domain.ErrCardNotFound
		}
		if err != nil {
			return err
		}
		plan, err := q.GetPlan(ctx, card.PlanID)
		if err != nil {
			return err
		}
		prod, err := q.GetProduct(ctx, card.ProductID)
		if err != nil {
			return err
		}
		if prod.Status != "active" {
			return domain.ErrProductRetired
		}
		if plan.Status != "active" {
			return domain.ErrPlanRetired
		}

		switch card.Status {
		case "unused":
			if card.Kind != "license" {
				return domain.ErrCardNotUsable
			}
			// 全新激活
			var usesLeft *int
			var expiresAt *time.Time
			switch plan.Kind {
			case "duration":
				t := now.AddDate(0, 0, plan.DurationDays)
				expiresAt = &t
			case "fixed":
				t := card.CreatedAt.AddDate(0, 0, plan.FixedExpiryDays)
				expiresAt = &t
				if t.Before(now) {
					return domain.ErrCardNotUsable
				}
			case "uses":
				u := plan.UsesTotal
				usesLeft = &u
			} // permanent: 两者均 nil

			lic, err := q.CreateLicense(ctx, &store.License{
				ProductID:    card.ProductID,
				PlanID:       card.PlanID,
				AgentID:      card.AgentID,
				OriginCardID: card.ID,
				Status:       "active",
				UsesLeft:     usesLeft,
				ExpiresAt:    expiresAt,
			})
			if err != nil {
				return err
			}
			// 次卡：初始设备绑定即消耗 1 次
			if plan.Kind == "uses" {
				left, cerr := q.ConsumeLicenseUse(ctx, lic.ID)
				if cerr != nil {
					return cerr
				}
				lic.UsesLeft = &left
				if left == 0 {
					if err := q.SetCardStatus(ctx, card.ID, "depleted"); err != nil {
						return err
					}
				}

			}
			dev, err := q.CreateDevice(ctx, &store.Device{
				LicenseID:       lic.ID,
				FingerprintHash: fpHash,
				DevicePub:       payload.DevicePub,
				PubKty:          payload.PubKty,
				TrustLevel:      payload.TrustLevel,
				HwSnapshot:      mustJSON(componentMap(payload.Components)),
				ClientVersion:   strPtr(payload.ClientVersion),
				LastIP:          strPtr(ip),
			})
			if err != nil {
				return err
			}
			if err := q.SetCardActivated(ctx, card.ID, lic.ID, now); err != nil {
				return err
			}
			if err := q.InsertLicenseEvent(ctx, lic.ID, "activated", "system", requestID, map[string]any{
				"card_prefix": card.Prefix, "device_id": dev.ID, "trust": payload.TrustLevel,
			}); err != nil {
				return err
			}
			result = s.buildResult(lic, dev, plan, prod, false)
			return nil

		case "active":
			lic, err := q.GetLicense(ctx, *card.LicenseID, true)
			if err != nil {
				return err
			}
			if lic.Status != "active" {
				return mapLicenseErr(lic.Status)
			}
			if lic.ExpiresAt != nil && lic.ExpiresAt.Before(now) {
				return domain.ErrLicenseExpired
			}
			// 已绑定设备重激活（同机）
			if dev, err := q.GetDeviceByFingerprint(ctx, lic.ID, fpHash); err == nil {
				if dev.DevicePub != payload.DevicePub || dev.PubKty != payload.PubKty {
					// 同机换了密钥（重装系统）：轮换设备公钥
					if err := q.RotateDevicePub(ctx, dev.ID, payload.DevicePub, payload.PubKty, payload.TrustLevel); err != nil {
						return err
					}
					dev.DevicePub = payload.DevicePub
					dev.PubKty = payload.PubKty
				}
				if err := q.InsertActivation(ctx, lic.ID, card.ID, dev.ID, "reactivation", ip); err != nil {
					return err
				}
				result = s.buildResult(lic, dev, plan, prod, true)
				return nil
			} else if err != store.ErrNoRows {
				return err
			}
			// 新设备
			// 锁定许可证行，保证设备上限检查与插入在并发激活下串行化。
			if _, err := q.GetLicense(ctx, lic.ID, true); err != nil {
				return err
			}
			n, err := q.CountActiveDevices(ctx, lic.ID)
			if err != nil {
				return err
			}
			if n >= plan.DeviceLimit {
				return domain.ErrDeviceLimit
			}
			// 次卡：新设备绑定消耗 1 次（重激活不消耗）
			if plan.Kind == "uses" {
				if _, cerr := q.ConsumeLicenseUse(ctx, lic.ID); cerr != nil {
					return domain.ErrCardDepleted
				}
			}
			dev, err := q.CreateDevice(ctx, &store.Device{
				LicenseID:       lic.ID,
				FingerprintHash: fpHash,
				DevicePub:       payload.DevicePub,
				PubKty:          payload.PubKty,
				TrustLevel:      payload.TrustLevel,
				HwSnapshot:      mustJSON(componentMap(payload.Components)),
				ClientVersion:   strPtr(payload.ClientVersion),
				LastIP:          strPtr(ip),
			})
			if err != nil {
				return err
			}
			if err := q.InsertActivation(ctx, lic.ID, card.ID, dev.ID, "rebind", ip); err != nil {
				return err
			}
			if err := q.InsertLicenseEvent(ctx, lic.ID, "device_bound", "system", requestID, map[string]any{
				"device_id": dev.ID, "active_devices": n + 1, "limit": plan.DeviceLimit,
			}); err != nil {
				return err
			}
			result = s.buildResult(lic, dev, plan, prod, false)
			return nil

		default:
			return mapCardErr(card.Status)
		}
	})
	if err != nil {
		return nil, err
	}

	// 4. 尝试登记在线（并发名额门在心跳阶段强制）：
	// 名额已满时激活仍成功（绑定完成），新设备首次心跳参与名额竞争。
	admitted, err := s.Cache.RenewOnline(ctx, result.LicenseID, result.DeviceID,
		time.Duration(result.LeaseTTL)*time.Second, result.ConcurrentLim)
	if err != nil {
		s.Risk.Record(ctx, "cache_error", "high", result.LicenseID, err.Error())
		return nil, domain.ErrRateLimited
	} else if !admitted {
		s.Risk.Record(ctx, "activation_seat_contended", "low", result.LicenseID,
			map[string]any{"device_id": result.DeviceID})
	}
	return result, nil
}

// buildResult 构造激活响应与租约载荷。
func (s *Services) buildResult(lic *store.License, dev *store.Device, plan *store.Plan, prod *store.Product, reactivated bool) *ActivationResult {
	res := &ActivationResult{
		LicenseID:     lic.ID,
		DeviceID:      dev.ID,
		ProductCode:   prod.Code,
		PlanCode:      plan.Code,
		Features:      plan.Features,
		HeartbeatSec:  plan.HeartbeatSec,
		LeaseTTL:      plan.LeaseTTL,
		OfflineGrace:  plan.OfflineGrace,
		ConcurrentLim: plan.ConcurrentLimit,
		LicenseExpiry: lic.ExpiresAt,
		Reactivated:   reactivated,
	}
	claims := crypto.LeaseClaims{
		Typ:    crypto.TokenTypeLease,
		JTI:    mustRandom(),
		Lic:    lic.ID,
		Prod:   prod.Code,
		Dev:    dev.ID,
		Feat:   plan.Features,
		Iss:    time.Now().Unix(),
		Exp:    time.Now().Unix() + int64(plan.LeaseTTL),
		Pol:    lic.PolicyVersion,
		HBI:    plan.HeartbeatSec,
		Grace:  plan.OfflineGrace,
		Status: string(domain.LicenseActive),
		MinVer: plan.MinClientVer,
	}
	if lic.ExpiresAt != nil {
		claims.LicExp = lic.ExpiresAt.Unix()
	}
	res.LeaseClaims = claims
	return res
}

// MintLease 用 Signer 签发租约令牌。
func (s *Services) MintLease(c crypto.LeaseClaims) (string, error) {
	return crypto.MintToken(s.Keys, c)
}

// fmtErrBadCard 对外统一为卡密格式错误（不暴露解析细节）。
var fmtErrBadCard = domain.ErrCardInvalidFormat

func mapCardErr(status string) error {
	switch status {
	case "frozen":
		return domain.ErrCardFrozen
	case "revoked":
		return domain.ErrCardRevoked
	case "voided":
		return domain.ErrCardVoided
	case "depleted":
		return domain.ErrCardDepleted
	}
	return domain.ErrCardNotUsable
}

func mapLicenseErr(status string) error {
	switch status {
	case "frozen":
		return domain.ErrLicenseFrozen
	case "revoked":
		return domain.ErrLicenseRevoked
	case "voided":
		return domain.ErrLicenseVoided
	}
	return domain.ErrLicenseRevoked
}

func componentMap(components []string) map[string]string {
	m := make(map[string]string, len(components))
	for i, c := range components {
		m[strconv.FormatInt(int64(i), 10)] = c
	}
	return m
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
