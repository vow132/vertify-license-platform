package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/store"
)

// HeartbeatRequest 心跳请求体（明文字段 + 设备签名头）。
type HeartbeatRequest struct {
	DeviceID      string `json:"device_id"`
	ClientVersion string `json:"client_version"`
}

// HeartbeatResponse 服务端心跳应答。
type HeartbeatResponse struct {
	Lease        string   `json:"lease"`
	ServerTime   int64    `json:"server_time"`
	NextHB       int      `json:"next_heartbeat_seconds"`
	Status       string   `json:"status"`
	Features     []string `json:"features"`
	LicenseExp   *int64   `json:"license_expiry"`
	PolicyVer    int64    `json:"policy_version"`
	MinVer       string   `json:"min_client_version"`
	OfflineGrace int      `json:"offline_grace_seconds"`
	Exp          int64    `json:"lease_exp"`
}

// Heartbeat 心跳：验证设备 PoP → 防重放 → 校验许可状态 → 原子并发续租 → 换发租约。
// 吊销/冻结在此一个心跳周期内传播到在线客户端。
func (s *Services) Heartbeat(ctx context.Context, ds *DeviceSignature, body []byte, ip string) (*HeartbeatResponse, error) {
	// 1. 身份：以设备公钥为锚（激活时已入库）
	dev, err := s.Store.Q().GetDeviceByPub(ctx, ds.Pub)
	if err == store.ErrNoRows {
		return nil, domain.ErrDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	if dev.Status != "active" {
		return nil, domain.ErrDeviceUnbound
	}
	if dev.ID != extractDeviceID(body) {
		return nil, domain.ErrBadSignature
	}

	// 2. 先验签，再消费 nonce/序列号；无效请求不得推进设备状态。
	if !ds.VerifyPub(dev.DevicePub, dev.PubKty, ds.Message("POST", "/v1/heartbeat", body)) {
		return nil, domain.ErrBadSignature
	}
	// 3. 防重放：时间窗 + nonce + 序列号
	if err := s.checkReplay(ctx, dev, ds, ip, "heartbeat"); err != nil {
		return nil, err
	}

	// 4. 许可状态（DB 事实）
	lic, err := s.Store.Q().GetLicense(ctx, dev.LicenseID, false)
	if err != nil {
		return nil, err
	}
	// 封禁执行：设备公钥
	if banned, _ := s.Store.Q().IsBanned(ctx, "device", dev.DevicePub); banned {
		return nil, domain.ErrBanned
	}
	now := time.Now()
	if lic.Status != "active" {
		return nil, mapLicenseErr(lic.Status)
	}
	if lic.ExpiresAt != nil && lic.ExpiresAt.Before(now) {
		return nil, domain.ErrLicenseExpired
	}

	plan, err := s.Store.Q().GetPlan(ctx, lic.PlanID)
	if err != nil {
		return nil, err
	}

	// 5. 版本策略 + 客户端版本封禁
	var req HeartbeatRequest
	_ = json.Unmarshal(body, &req)
	if req.ClientVersion != "" && !versionRe.MatchString(req.ClientVersion) {
		return nil, domain.ErrVersionTooOld
	}
	if req.ClientVersion != "" {
		if banned, banErr := s.Store.Q().IsBanned(ctx, "client_version", req.ClientVersion); banErr != nil {
			return nil, banErr
		} else if banned {
			return nil, domain.ErrBanned
		}
	}

	if plan.MinClientVer != "" && req.ClientVersion != "" &&
		CompareVersion(req.ClientVersion, plan.MinClientVer) < 0 {
		return nil, domain.ErrVersionTooOld
	}

	// 6. 原子并发续租
	ok, err := s.Cache.RenewOnline(ctx, lic.ID, dev.ID,
		time.Duration(plan.LeaseTTL)*time.Second, plan.ConcurrentLimit)
	if err != nil {
		s.Risk.Record(ctx, "cache_error", "low", lic.ID, err.Error())
		// Redis 故障降级：允许心跳（租约仍由 DB 状态裁决），避免整体不可用
	} else if !ok {
		return nil, domain.ErrConcurrentLimit
	}

	// 7. 元数据 + DB 序列号
	if err := s.Store.Q().BumpDeviceHeartbeat(ctx, dev.ID, ds.Seq, ip, req.ClientVersion); err != nil {
		return nil, err
	}

	// 8. 换发租约
	claims := crypto.LeaseClaims{
		Typ:    crypto.TokenTypeLease,
		JTI:    mustRandom(),
		Lic:    lic.ID,
		Prod:   productCodeOf(ctx, s, lic.ProductID),
		Dev:    dev.ID,
		Feat:   plan.Features,
		Iss:    now.Unix(),
		Exp:    now.Unix() + int64(plan.LeaseTTL),
		Pol:    lic.PolicyVersion,
		HBI:    plan.HeartbeatSec,
		Grace:  plan.OfflineGrace,
		Status: string(domain.LicenseActive),
		MinVer: plan.MinClientVer,
	}
	if lic.ExpiresAt != nil {
		claims.LicExp = lic.ExpiresAt.Unix()
	}
	lease, err := crypto.MintToken(s.Keys, claims)
	if err != nil {
		return nil, err
	}
	resp := &HeartbeatResponse{
		Lease:        lease,
		ServerTime:   now.Unix(),
		NextHB:       plan.HeartbeatSec,
		Status:       "active",
		Features:     plan.Features,
		PolicyVer:    lic.PolicyVersion,
		MinVer:       plan.MinClientVer,
		OfflineGrace: plan.OfflineGrace,
		Exp:          claims.Exp,
	}
	if lic.ExpiresAt != nil {
		t := lic.ExpiresAt.Unix()
		resp.LicenseExp = &t
	}
	return resp, nil
}

func productCodeOf(ctx context.Context, s *Services, productID string) string {
	p, err := s.Store.Q().GetProduct(ctx, productID)
	if err != nil {
		return ""
	}
	return p.Code
}

func extractDeviceID(body []byte) string {
	var req HeartbeatRequest
	_ = json.Unmarshal(body, &req)
	return req.DeviceID
}

// checkActivationReplay 激活尚未有数据库设备行，只使用 Redis 的一次性 nonce/序列号；
// Redis 不可用时拒绝激活，避免把重放保护降级为空。
func (s *Services) checkActivationReplay(ctx context.Context, ds *DeviceSignature, pub, ip string) error {
	now := time.Now()
	skew := s.Cfg.MaxClockSkew
	if ds.TS < now.Add(-skew).Unix() || ds.TS > now.Add(skew).Unix() {
		return domain.ErrReplayDetected
	}
	ok, err := s.Cache.ConsumeNonce(ctx, "activate", ds.Nonce, s.Cfg.ReplayWindow+skew)
	if err != nil {
		s.Risk.Record(ctx, "cache_error", "high", "activate:"+pub, err.Error())
		return domain.ErrRateLimited
	}
	if !ok {
		s.Risk.Record(ctx, "replay", "high", "activate:"+pub, map[string]any{"ip": ip})
		return domain.ErrReplayDetected
	}
	good, _, err := s.Cache.CheckSeq(ctx, "activate:"+pub, ds.Seq, time.Duration(s.Cfg.ReplayWindow)*10)
	if err != nil {
		s.Risk.Record(ctx, "cache_error", "high", "activate:"+pub, err.Error())
		return domain.ErrRateLimited
	}
	if !good {
		return domain.ErrSeqRegression
	}
	return nil
}
func (s *Services) checkReplay(ctx context.Context, dev *store.Device, ds *DeviceSignature, ip, scope string) error {

	now := time.Now()
	skew := s.Cfg.MaxClockSkew
	if ds.TS < now.Add(-skew).Unix() || ds.TS > now.Add(skew).Unix() {
		s.Risk.Record(ctx, "stale_timestamp", "medium", dev.ID, map[string]any{"ts": ds.TS, "ip": ip})
		return domain.ErrReplayDetected
	}
	ok, err := s.Cache.ConsumeNonce(ctx, scope, ds.Nonce, s.Cfg.ReplayWindow+skew)
	if err != nil {
		s.Risk.Record(ctx, "cache_error", "high", dev.ID, err.Error())
		if scope == "activate" {
			return domain.ErrRateLimited
		}
		// 心跳/续费可由数据库序列号兜底
	} else if !ok {
		s.Risk.Record(ctx, "replay", "high", dev.ID, map[string]any{"scope": scope, "ip": ip})
		return domain.ErrReplayDetected
	}
	good, known, seqErr := s.Cache.CheckSeq(ctx, dev.ID, ds.Seq, time.Duration(s.Cfg.ReplayWindow)*10)
	if seqErr != nil || !known {
		accepted, dbErr := s.Store.Q().AcceptDeviceSeq(ctx, dev.ID, ds.Seq)
		if dbErr != nil {
			return dbErr
		}
		if !accepted {
			s.Risk.Record(ctx, "seq_regression", "high", dev.ID, map[string]any{"seq": ds.Seq})
			return domain.ErrSeqRegression
		}
		return nil
	}
	if !good {
		s.Risk.Record(ctx, "seq_regression", "high", dev.ID, map[string]any{"seq": ds.Seq})
		return domain.ErrSeqRegression
	}
	return nil
}

// RedeemPayload 兑换续费卡载荷（信封加密）。
type RedeemPayload struct {
	Card string `json:"card"`
}

type RedeemResult struct {
	LicenseID   string             `json:"license_id"`
	NewExpiry   *time.Time         `json:"new_expiry"`
	DaysAdded   int                `json:"days_added"`
	Lease       string             `json:"lease"`
	LeaseClaims crypto.LeaseClaims `json:"-"`
}

// Redeem 在已激活许可证上兑换续费卡。要求设备 PoP（续期目标 = 该设备所属许可）。
func (s *Services) Redeem(ctx context.Context, envelopeJSON []byte, ds *DeviceSignature, ip, requestID string) (*RedeemResult, error) {
	pt, err := crypto.OpenEnvelope(envelopeJSON, "", s.Kex, crypto.AADContext("redeem"))
	if err != nil {
		return nil, err
	}
	var payload RedeemPayload
	if err := unmarshalStrict(pt, &payload); err != nil || payload.Card == "" {
		return nil, domain.ErrCardInvalidFormat
	}

	// 设备身份与签名先完成，再消费重放状态。
	dev, err := s.Store.Q().GetDeviceByPub(ctx, ds.Pub)
	if err == store.ErrNoRows {
		return nil, domain.ErrDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	if dev.Status != "active" {
		return nil, domain.ErrDeviceUnbound
	}
	if !ds.VerifyPub(dev.DevicePub, dev.PubKty, ds.Message("POST", "/v1/redeem", envelopeJSON)) {
		return nil, domain.ErrBadSignature
	}
	if err := s.checkReplay(ctx, dev, ds, ip, "redeem"); err != nil {
		return nil, err
	}

	normalized, err := crypto.NormalizeCard(payload.Card)
	if err != nil {
		return nil, domain.ErrCardInvalidFormat
	}
	// 封禁执行：卡密前缀
	if banned, _ := s.Store.Q().IsBanned(ctx, "card_prefix", crypto.CardPrefix(normalized)); banned {
		return nil, domain.ErrBanned
	}
	lookup := s.CardLookup(normalized)
	now := time.Now()
	var result *RedeemResult

	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		lic, err := q.GetLicense(ctx, dev.LicenseID, true)
		if err != nil {
			return err
		}
		if lic.Status != "active" {
			return mapLicenseErr(lic.Status)
		}
		if lic.ExpiresAt == nil {
			// 永久/次卡许可证不接受时长续费（避免把永久证改成限时）
			return domain.ErrCardNotUsable
		}
		card, err := q.GetCardByLookup(ctx, lookup, true)
		if err == store.ErrNoRows {
			return domain.ErrCardNotFound
		}
		if err != nil {
			return err
		}
		if card.Kind != "renewal" {
			return domain.ErrCardNotUsable
		}
		if card.ProductID != lic.ProductID {
			return domain.ErrCardNotUsable // 续费卡与许可证产品不一致
		}
		if card.Status != "unused" {
			return mapCardErr(card.Status)
		}
		plan, err := q.GetPlan(ctx, card.PlanID)
		if err != nil {
			return err
		}
		if plan.DurationDays <= 0 {
			return domain.ErrCardNotUsable
		}
		licensePlan, err := q.GetPlan(ctx, lic.PlanID)
		if err != nil {
			return err
		}
		if licensePlan.Status != "active" {
			return domain.ErrPlanRetired
		}
		oldExp := lic.ExpiresAt
		newExp, err := q.ExtendLicense(ctx, lic.ID, plan.DurationDays)
		if err != nil {
			return err
		}
		if err := q.SetCardStatus(ctx, card.ID, "depleted"); err != nil {
			return err
		}
		if err := q.InsertRenewal(ctx, lic.ID, card.ID, plan.DurationDays, oldExp, newExp); err != nil {
			return err
		}
		if err := q.InsertLicenseEvent(ctx, lic.ID, "renewed", "device", requestID, map[string]any{
			"card_prefix": card.Prefix, "days": plan.DurationDays, "new_expiry": newExp,
		}); err != nil {
			return err
		}
		claims := crypto.LeaseClaims{
			Typ: crypto.TokenTypeLease, JTI: mustRandom(), Lic: lic.ID, Dev: dev.ID,
			Iss: now.Unix(), Exp: now.Unix() + int64(licensePlan.LeaseTTL),
			Pol: lic.PolicyVersion, HBI: licensePlan.HeartbeatSec, Grace: licensePlan.OfflineGrace,
			Status: string(domain.LicenseActive), Feat: licensePlan.Features,
		}
		if lic.ExpiresAt != nil {
			claims.LicExp = lic.ExpiresAt.Unix()
		}
		result = &RedeemResult{
			LicenseID: lic.ID, NewExpiry: newExp, DaysAdded: plan.DurationDays, LeaseClaims: claims,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	lease, err := crypto.MintToken(s.Keys, result.LeaseClaims)
	if err != nil {
		return nil, err
	}
	result.Lease = lease
	return result, nil
}

// Deactivate 设备自助解绑（换机/卸载时释放名额）。
func (s *Services) Deactivate(ctx context.Context, ds *DeviceSignature, body []byte, ip, requestID string) error {
	dev, err := s.Store.Q().GetDeviceByPub(ctx, ds.Pub)
	if err == store.ErrNoRows {
		return domain.ErrDeviceNotFound
	}
	if err != nil {
		return err
	}
	if dev.Status != "active" {
		return domain.ErrDeviceUnbound
	}
	if !ds.VerifyPub(dev.DevicePub, dev.PubKty, ds.Message("POST", "/v1/deactivate", body)) {
		return domain.ErrBadSignature
	}
	if err := s.checkReplay(ctx, dev, ds, ip, "deactivate"); err != nil {
		return err
	}
	unbound, err := s.Store.Q().UnbindDevice(ctx, dev.ID, "self")
	if errors.Is(err, store.ErrNoRows) {
		return domain.ErrDeviceUnbound
	}
	if err != nil {
		return err
	}
	if err := s.Cache.DropOnline(ctx, unbound.LicenseID, unbound.ID); err != nil {
		s.Risk.Record(ctx, "cache_error", "low", unbound.LicenseID, err.Error())
	}
	return s.Store.Q().InsertLicenseEvent(ctx, unbound.LicenseID, "device_unbound", "self", requestID, map[string]any{
		"device_id": unbound.ID, "ip": ip,
	})
}
