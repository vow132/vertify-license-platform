package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/store"
)

// ===== 制卡与卡密管理 =====

type CreateBatchRequest struct {
	ProductID    string `json:"product_id"`
	PlanID       string `json:"plan_id"`
	DurationDays int    `json:"duration_days"` // 自定义时长：PlanID 为空时按此天数自动建套餐（仅总经销/管理员）
	AgentID      string `json:"agent_id"`
	Kind         string `json:"kind"` // license | renewal
	Quantity     int    `json:"quantity"`
	Prefix       string `json:"prefix"`
	Note         string `json:"note"`
}

type ImportCardRequest struct {
	ProductID string   `json:"product_id"`
	PlanID    string   `json:"plan_id"`
	Cards     []string `json:"cards"`
	Kind      string   `json:"kind"`
	Note      string   `json:"note"`
}

func (s *Services) ImportCards(ctx context.Context, ac *AdminContext, req *ImportCardRequest, ip, requestID string) (int, error) {
	if len(req.Cards) == 0 || len(req.Cards) > 10000 {
		return 0, errors.New("导入数量必须是1-10000")
	}
	plan, err := s.Store.Q().GetPlan(ctx, req.PlanID)
	if err != nil {
		return 0, err
	}
	prod, err := s.Store.Q().GetProduct(ctx, req.ProductID)
	if err != nil {
		return 0, err
	}
	if plan.ProductID != prod.ID {
		return 0, errors.New("套餐不属于当前产品")
	}
	if prod.Status != "active" {
		return 0, domain.ErrProductRetired
	}
	if plan.Status != "active" {
		return 0, domain.ErrPlanRetired
	}
	kind := req.Kind
	if kind == "" {
		kind = "license"
	}
	if kind != "license" && kind != "renewal" {
		return 0, errors.New("卡类型无效")
	}
	seeds := make([]store.CardSeed, 0, len(req.Cards))
	seen := map[string]bool{}
	batchPrefix := ""
	for _, raw := range req.Cards {
		norm, e := crypto.NormalizeCard(raw)
		if e != nil {
			return 0, errors.New("存在格式错误的卡密")
		}
		lookup := s.CardLookup(norm)
		if seen[lookup] {
			return 0, errors.New("导入卡密重复")
		}
		seen[lookup] = true
		prefix := crypto.CardPrefix(norm)
		if batchPrefix == "" {
			batchPrefix = prefix
		} else if prefix != batchPrefix {
			return 0, errors.New("同一批次卡密前缀必须一致")
		}
		secretCt, secretNonce, secretKid, e := s.EncryptCardSecret("", "", prod.ID, norm)
		if e != nil {
			return 0, e
		}
		seeds = append(seeds, store.CardSeed{
			Lookup: lookup, Prefix: prefix, Kind: kind,
			UsesTotal: plan.UsesTotal, UsesLeft: plan.UsesTotal,
			SecretCiphertext: secretCt, SecretNonce: secretNonce, SecretKeyVersion: secretKid,
		})
	}
	note := strings.TrimSpace(req.Note)
	var noteP *string
	if note != "" {
		noteP = &note
	}
	var result *store.CreateBatchResult
	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		var e error
		result, e = q.CreateBatch(ctx, &store.CardBatch{ProductID: prod.ID, PlanID: plan.ID, Quantity: len(seeds), Prefix: batchPrefix, Note: noteP, CreatedBy: ac.Admin.ID}, seeds)
		return e
	})
	if err != nil {
		return 0, err
	}
	s.Audit(ctx, ac, "batch.import", "card_batch", result.Batch.ID, nil, map[string]any{"quantity": len(seeds), "product": prod.Code, "plan": plan.Code, "kind": kind}, nil, ip, requestID)
	return len(seeds), nil
}

type BatchResult struct {
	Batch *store.CardBatch `json:"batch"`
	Cards []string         `json:"cards"`
}

// CreateCardBatch 制卡。明文卡密仅在返回值中出现一次；数据库只存 HMAC。
func (s *Services) CreateCardBatch(ctx context.Context, ac *AdminContext, req *CreateBatchRequest, ip, requestID string) (*BatchResult, error) {
	if req.Quantity < 1 || req.Quantity > 100_000 {
		return nil, fmt.Errorf("quantity out of range")
	}
	if _, err := crypto.ValidateCardPrefix(req.Prefix); err != nil {
		return nil, errors.New("前缀只能使用大写字母和数字2-9，长度不超过8位")
	}
	kind := req.Kind
	if kind == "" {
		kind = "license"
	}
	if kind != "license" && kind != "renewal" {
		return nil, fmt.Errorf("kind must be license|renewal")
	}
	var plan *store.Plan
	var err error
	if req.PlanID == "" {
		// 自定义时长：自动查找/创建 duration 套餐（仅总经销/管理员；代理必须选已定价套餐，防止 0 元绕过计费）
		if ac.Admin.Role == string(domain.AdminAgent) {
			return nil, errors.New("agents must choose a priced plan")
		}
		if req.DurationDays <= 0 || req.DurationDays > 36500 {
			return nil, errors.New("duration_days must be 1-36500")
		}
		if plan, err = s.findOrCreateCustomPlan(ctx, req.ProductID, req.DurationDays); err != nil {
			return nil, err
		}
	} else {
		if plan, err = s.Store.Q().GetPlan(ctx, req.PlanID); err != nil {
			return nil, err
		}
	}
	// 自定义时长路径：plan_id 原为空，落库前必须指向自动创建的套餐
	req.PlanID = plan.ID
	prod, err := s.Store.Q().GetProduct(ctx, req.ProductID)
	if err != nil {
		return nil, err
	}
	if plan.ProductID != prod.ID {
		return nil, errors.New("plan does not belong to product")
	}
	if prod.Status != "active" {
		return nil, domain.ErrProductRetired
	}
	if plan.Status != "active" {
		return nil, domain.ErrPlanRetired
	}

	prefix, _ := crypto.ValidateCardPrefix(req.Prefix)
	var plaintexts []string
	if prefix == "" {
		plaintexts, err = crypto.GenerateCardBatch(req.Quantity)
	} else {
		plaintexts, err = crypto.GenerateCardBatchWithPrefix(req.Quantity, prefix)
	}
	if err != nil {
		return nil, err
	}
	seeds := make([]store.CardSeed, len(plaintexts))
	for i, pt := range plaintexts {
		norm, err := crypto.NormalizeCard(pt)
		if err != nil {
			return nil, err
		}
		seeds[i] = store.CardSeed{Lookup: s.CardLookup(norm), Prefix: crypto.CardPrefix(norm), Kind: kind, UsesTotal: plan.UsesTotal, UsesLeft: plan.UsesTotal}
		secretCt, secretNonce, secretKid, serr := s.EncryptCardSecret("", "", req.ProductID, norm)
		if serr != nil {
			return nil, serr
		}
		seeds[i].SecretCiphertext, seeds[i].SecretNonce, seeds[i].SecretKeyVersion = secretCt, secretNonce, secretKid

	}
	var agentID *string
	if req.AgentID != "" {
		agentID = &req.AgentID
	}
	note := strings.TrimSpace(req.Note)
	var noteP *string
	if note != "" {
		noteP = &note
	}
	// 事务写入批次与全部卡密行（中途失败整体回滚，杜绝残缺批次）。
	// 计费：批次归属代理且套餐有定价时，在同一事务内按 数量×单价 扣代理余额。
	var res *store.CreateBatchResult
	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		var txErr error
		res, txErr = q.CreateBatch(ctx, &store.CardBatch{
			AgentID:   agentID,
			ProductID: req.ProductID,
			PlanID:    req.PlanID,
			Quantity:  req.Quantity,
			Prefix:    prefix,

			Note:      noteP,
			CreatedBy: ac.Admin.ID,
		}, seeds)
		if txErr != nil {
			return txErr
		}
		if agentID != nil && plan.PriceCents > 0 {
			if int64(req.Quantity) > math.MaxInt64/plan.PriceCents {
				return errors.New("制卡费用超出金额范围")
			}
			cost := int64(req.Quantity) * plan.PriceCents
			after, derr := q.DeductAgentBalance(ctx, *agentID, cost)
			if derr != nil {
				if derr == store.ErrNoRows {
					return domain.ErrInsufficientBalance
				}
				return derr
			}
			batchID := res.Batch.ID
			if terr := q.InsertAgentTransaction(ctx, *agentID, -cost, after, "batch_purchase", &batchID,
				strPtr("制卡 "+strconv.Itoa(req.Quantity)+"×"+plan.Code), strPtr(ac.Admin.ID)); terr != nil {
				return terr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, ac, "batch.create", "card_batch", res.Batch.ID,
		nil, map[string]any{"quantity": req.Quantity, "product": prod.Code, "plan": plan.Code, "kind": kind},
		nil, ip, requestID)
	return &BatchResult{Batch: res.Batch, Cards: plaintexts}, nil
}

// AgentAdjustBalance 总经销给代理调整余额（充值正数 / 调差负数），写资金流水。
func (s *Services) AgentAdjustBalance(ctx context.Context, ac *AdminContext, agentID string, amountCents int64, note, ip, requestID string) (int64, error) {
	if amountCents == 0 {
		return 0, errors.New("amount must be non-zero")
	}
	var after int64
	kind := "topup"
	if amountCents < 0 {
		kind = "adjust"
	}
	err := s.Store.WithTx(ctx, func(q *store.Queries) error {
		if _, err := q.GetAgent(ctx, agentID); err != nil {
			if errors.Is(err, store.ErrNoRows) {
				return domain.ErrAgentNotFound
			}
			return err
		}
		var err error
		after, err = q.TopUpAgentBalance(ctx, agentID, amountCents)
		if errors.Is(err, store.ErrNoRows) {
			return domain.ErrInsufficientBalance
		}
		if err != nil {
			return err
		}
		return q.InsertAgentTransaction(ctx, agentID, amountCents, after, kind, nil,
			strPtr(note), strPtr(ac.Admin.ID))
	})
	if err != nil {
		return 0, err
	}
	s.Audit(ctx, ac, "agent.balance", "agent", agentID, nil,
		map[string]any{"amount_cents": amountCents, "balance_after": after, "note": note}, nil, ip, requestID)
	return after, nil
}

// agentDenied 判断 agent 角色是否在访问非本代理的资源。
// 命中时调用方应返回 404（防资源枚举），不能返回 403。
func agentDenied(ac *AdminContext, ownerAgentID *string) bool {
	if ac == nil || ac.Admin.Role != string(domain.AdminAgent) {
		return false
	}
	return ac.Admin.AgentID == nil || ownerAgentID == nil || *ownerAgentID != *ac.Admin.AgentID
}

// CardAction 冻结/解冻/吊销/作废。
func (s *Services) CardAction(ctx context.Context, ac *AdminContext, cardID, action, reason, ip, requestID string) error {
	card, err := s.Store.Q().GetCardByID(ctx, cardID)
	if err != nil {
		return err
	}
	if agentDenied(ac, card.AgentID) {
		return domain.ErrCardNotFound
	}
	before := map[string]any{"status": card.Status}
	var after map[string]any
	var targetStatus string
	var fromStatus string
	switch action {
	case "freeze":
		if card.Status != "active" && card.Status != "unused" {
			return domain.ErrCardNotUsable
		}
		fromStatus, targetStatus = card.Status, "frozen"
		after = map[string]any{"status": targetStatus}
	case "unfreeze":
		if card.Status != "frozen" {
			return domain.ErrCardNotUsable
		}
		fromStatus, targetStatus = "frozen", "unused"
		if card.ActivatedAt != nil {
			targetStatus = "active"
		}
		after = map[string]any{"status": targetStatus}
	case "revoke", "void":
		if card.Status == "revoked" || card.Status == "voided" {
			return domain.ErrCardNotUsable
		}
		targetStatus = action
		if action == "void" {
			targetStatus = "voided"
		}
		after = map[string]any{"status": targetStatus}
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		if fromStatus != "" {
			if err := q.TransitionCardStatus(ctx, card.ID, fromStatus, targetStatus); err != nil {
				return err
			}
		} else if err := q.TransitionCardToTerminal(ctx, card.ID, targetStatus); err != nil {
			return err
		}
		if card.LicenseID == nil {
			return nil
		}
		licenseID := *card.LicenseID
		switch action {
		case "freeze":
			return q.TransitionLicense(ctx, licenseID, "active", "frozen")
		case "unfreeze":
			return q.TransitionLicense(ctx, licenseID, "frozen", "active")
		case "revoke", "void":
			if err := q.TransitionLicenseTerminal(ctx, licenseID, targetStatus); err != nil {
				return err
			}
			return q.InsertLicenseEvent(ctx, licenseID, targetStatus, "admin:"+ac.Admin.ID, requestID, map[string]any{"reason": reason})
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.Audit(ctx, ac, "card."+action, "card", card.ID, before, after, map[string]any{"reason": reason, "prefix": card.Prefix}, ip, requestID)
	return nil
}

// LicenseAction 管理员对许可证的处置。
func (s *Services) LicenseAction(ctx context.Context, ac *AdminContext, licenseID, action, reason, ip, requestID string) error {
	lic, err := s.Store.Q().GetLicense(ctx, licenseID, false)
	if err != nil {
		return err
	}
	if agentDenied(ac, lic.AgentID) {
		return domain.ErrCardNotFound
	}
	before := map[string]any{"status": lic.Status}
	var after map[string]any
	actor := "admin:" + ac.Admin.ID
	if action != "freeze" && action != "unfreeze" && action != "revoke" && action != "void" {
		return fmt.Errorf("unknown action %q", action)
	}
	var target string
	switch action {
	case "freeze":
		if lic.Status != "active" {
			return domain.ErrLicenseRevoked
		}
		target = "frozen"
	case "unfreeze":
		if lic.Status != "frozen" {
			return domain.ErrLicenseRevoked
		}
		target = "active"
	case "revoke", "void":
		if lic.Status == "revoked" || lic.Status == "voided" {
			return domain.ErrLicenseRevoked
		}
		target = action
		if action == "void" {
			target = "voided"
		}
	}
	after = map[string]any{"status": target}
	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		if action == "freeze" || action == "unfreeze" {
			return q.TransitionLicense(ctx, lic.ID, lic.Status, target)
		}
		if err := q.TransitionLicenseTerminal(ctx, lic.ID, target); err != nil {
			return err
		}
		if err := q.TransitionCardToTerminal(ctx, lic.OriginCardID, target); err != nil {
			return err
		}
		return q.InsertLicenseEvent(ctx, lic.ID, target, actor, requestID, map[string]any{"reason": reason})
	})
	if err != nil {
		return err
	}
	s.Audit(ctx, ac, "license."+action, "license", lic.ID, before, after, map[string]any{"reason": reason}, ip, requestID)
	return nil
}

// UnbindDevice 管理员解绑设备（换机审批动作）。
func (s *Services) UnbindDevice(ctx context.Context, ac *AdminContext, deviceID, reason, ip, requestID string) (*store.Device, error) {
	// 归属校验：agent 角色只能解绑本代理许可证下的设备
	dev0, err := s.Store.Q().GetDevice(ctx, deviceID)
	if errors.Is(err, store.ErrNoRows) {
		return nil, domain.ErrDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	lic0, err := s.Store.Q().GetLicense(ctx, dev0.LicenseID, false)
	if err != nil {
		return nil, err
	}
	if agentDenied(ac, lic0.AgentID) {
		return nil, domain.ErrDeviceNotFound
	}
	dev, err := s.Store.Q().UnbindDevice(ctx, deviceID, "admin:"+ac.Admin.ID)
	if errors.Is(err, store.ErrNoRows) {
		return nil, domain.ErrDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = s.Cache.DropOnline(ctx, dev.LicenseID, dev.ID)
	_ = s.Store.Q().InsertLicenseEvent(ctx, dev.LicenseID, "device_unbound", "admin:"+ac.Admin.ID, requestID,
		map[string]any{"device_id": dev.ID, "reason": reason})
	s.Audit(ctx, ac, "device.unbind", "device", dev.ID, nil,
		map[string]any{"status": "unbound", "reason": reason}, nil, ip, requestID)
	return dev, nil
}

// SetLicenseNote 备注。
func (s *Services) SetLicenseNote(ctx context.Context, ac *AdminContext, licenseID, note, ip, requestID string) error {
	lic, err := s.Store.Q().GetLicense(ctx, licenseID, false)
	if err != nil {
		return err
	}
	if agentDenied(ac, lic.AgentID) {
		return domain.ErrCardNotFound
	}
	if err := s.Store.Q().SetLicenseNote(ctx, licenseID, note); err != nil {
		return err
	}
	s.Audit(ctx, ac, "license.note", "license", licenseID, nil,
		map[string]any{"note": note}, nil, ip, requestID)
	return nil
}

// ===== 产品 / 套餐 =====

// CreateProduct 创建产品。code 为空时自动生成（P+8 位无歧义随机大写字母数字），
// SDK 与数据模型以 code 关联产品，故保留该标识但无需人工输入。
func (s *Services) CreateProduct(ctx context.Context, ac *AdminContext, code, name, ip, requestID string) (*store.Product, error) {
	if strings.TrimSpace(code) == "" {
		for attempt := 0; attempt < 5; attempt++ {
			code = "P" + autoSuffix()
			if _, err := s.Store.Q().GetProductByCode(ctx, code); err == store.ErrNoRows {
				break
			}
		}
	}
	p, err := s.Store.Q().CreateProduct(ctx, code, name)
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, ac, "product.create", "product", p.ID, nil, p, nil, ip, requestID)
	return p, nil
}

func (s *Services) ProductStatus(ctx context.Context, ac *AdminContext, id, status, ip, requestID string) error {
	if status != "active" && status != "retired" {
		return errors.New("bad status")
	}
	if err := s.Store.Q().SetProductStatus(ctx, id, status); err != nil {
		return err
	}
	s.Audit(ctx, ac, "product.status", "product", id, nil, map[string]any{"status": status}, nil, ip, requestID)
	return nil
}

func (s *Services) CreatePlan(ctx context.Context, ac *AdminContext, p *store.Plan, ip, requestID string) (*store.Plan, error) {
	if p.Features == nil {
		p.Features = []string{}
	}
	// 策略默认值（零值会违反 DB CHECK，且语义上不应缺省）
	if p.HeartbeatSec == 0 {
		p.HeartbeatSec = 60
	}
	if p.LeaseTTL == 0 {
		p.LeaseTTL = 300
	}
	if p.RebindCooldownH == 0 {
		p.RebindCooldownH = 24
	}
	if p.MonthlyRebind == 0 {
		p.MonthlyRebind = 2
	}
	if err := validatePlan(p); err != nil {
		return nil, err
	}
	pl, err := s.Store.Q().CreatePlan(ctx, p)
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, ac, "plan.create", "plan", pl.ID, nil, pl, nil, ip, requestID)
	return pl, nil
}

func validatePlan(p *store.Plan) error {
	switch p.Kind {
	case "duration":
		if p.DurationDays <= 0 {
			return errors.New("duration plan needs duration_days > 0")
		}
	case "fixed":
		if p.FixedExpiryDays <= 0 {
			return errors.New("fixed plan needs fixed_expiry_days > 0")
		}
	case "permanent":
		// ok
	case "uses":
		if p.UsesTotal <= 0 {
			return errors.New("uses plan needs uses_total > 0")
		}
	default:
		return errors.New("kind must be duration|fixed|permanent|uses")
	}
	if p.DeviceLimit < 1 || p.ConcurrentLimit < 1 {
		return errors.New("device_limit / concurrent_limit must be >= 1")
	}
	return nil
}

func (s *Services) UpdatePlan(ctx context.Context, ac *AdminContext, id string, in *store.Plan, ip, requestID string) (*store.Plan, error) {
	old, err := s.Store.Q().GetPlan(ctx, id)
	if err != nil {
		return nil, err
	}
	in.ID, in.ProductID, in.Code, in.Kind, in.Status, in.CreatedAt = old.ID, old.ProductID, old.Code, old.Kind, old.Status, old.CreatedAt
	if in.Features == nil {
		in.Features = []string{}
	}
	if in.HeartbeatSec == 0 {
		in.HeartbeatSec = old.HeartbeatSec
	}
	if in.LeaseTTL == 0 {
		in.LeaseTTL = old.LeaseTTL
	}
	if in.RebindCooldownH == 0 {
		in.RebindCooldownH = old.RebindCooldownH
	}
	if in.MonthlyRebind == 0 {
		in.MonthlyRebind = old.MonthlyRebind
	}
	if err := validatePlan(in); err != nil {
		return nil, err
	}
	if in.PriceCents < 0 {
		return nil, errors.New("price cannot be negative")
	}
	var updated *store.Plan
	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		var e error
		updated, e = q.UpdatePlan(ctx, in)
		if e != nil {
			return e
		}
		return q.TouchLicensesPolicy(ctx, id)
	})
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, ac, "plan.update", "plan", id, old, updated, nil, ip, requestID)
	return updated, nil
}

func (s *Services) DeletePlan(ctx context.Context, ac *AdminContext, id, ip, requestID string) error {
	p, err := s.Store.Q().GetPlan(ctx, id)
	if err != nil {
		return err
	}
	n, err := s.Store.Q().CountPlanReferences(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return domain.ErrPlanInUse
	}
	if err := s.Store.Q().DeletePlan(ctx, id); err != nil {
		return err
	}
	s.Audit(ctx, ac, "plan.delete", "plan", id, p, nil, nil, ip, requestID)
	return nil
}

func (s *Services) PlanStatus(ctx context.Context, ac *AdminContext, id, status, ip, requestID string) error {
	if status != "active" && status != "retired" {
		return errors.New("bad status")
	}
	err := s.Store.WithTx(ctx, func(q *store.Queries) error {
		if err := q.SetPlanStatus(ctx, id, status); err != nil {
			return err
		}
		return q.TouchLicensesPolicy(ctx, id)
	})
	if err != nil {
		return err
	}
	s.Audit(ctx, ac, "plan.status", "plan", id, nil, map[string]any{"status": status}, nil, ip, requestID)
	return nil
}

// ===== 代理商 / 管理员 =====

func (s *Services) CreateAgent(ctx context.Context, ac *AdminContext, name string, parentID *string, ip, requestID string) (*store.Agent, error) {
	if ac != nil && ac.Admin.Role == string(domain.AdminAgent) {
		if ac.Admin.AgentID == nil || parentID == nil || *parentID != *ac.Admin.AgentID {
			return nil, domain.ErrCardNotFound
		}
	}
	a, err := s.Store.Q().CreateAgent(ctx, name, parentID)
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, ac, "agent.create", "agent", a.ID, nil, a, nil, ip, requestID)
	return a, nil
}

func (s *Services) AgentStatus(ctx context.Context, ac *AdminContext, id, status, ip, requestID string) error {
	if status != "active" && status != "suspended" {
		return errors.New("bad status")
	}
	if ac != nil && ac.Admin.Role == string(domain.AdminAgent) {
		ag, err := s.Store.Q().GetAgent(ctx, id)
		if err != nil || ac.Admin.AgentID == nil || ag.ID != *ac.Admin.AgentID {
			return domain.ErrCardNotFound
		}
	}
	if err := s.Store.Q().SetAgentStatus(ctx, id, status); err != nil {
		return err
	}
	s.Audit(ctx, ac, "agent.status", "agent", id, nil, map[string]any{"status": status}, nil, ip, requestID)
	return nil
}

func (s *Services) CreateAdmin(ctx context.Context, ac *AdminContext, username, displayName, password, role string, agentID *string, ip, requestID string) (*store.Admin, error) {
	if ac.Admin.Role != string(domain.AdminSuperAdmin) {
		return nil, errors.New("only superadmin can create admins")
	}
	switch domain.AdminRole(role) {
	case domain.AdminSuperAdmin, domain.AdminAdmin, domain.AdminAgent, domain.AdminAuditor, domain.AdminViewer:
	default:
		return nil, errors.New("bad role")
	}
	if len(password) < 12 {
		return nil, errors.New("password must be >= 12 chars")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	a, err := s.Store.Q().CreateAdmin(ctx, &store.Admin{
		Username: username, PasswordHash: hash, DisplayName: displayName,
		Role: role, AgentID: agentID, MustChangePassword: true,
	})
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, ac, "admin.create", "admin", a.ID, nil,
		map[string]any{"username": a.Username, "role": a.Role}, nil, ip, requestID)
	return a, nil
}

func (s *Services) SetAdminStatus(ctx context.Context, ac *AdminContext, adminID, status, ip, requestID string) error {
	if ac.Admin.Role != string(domain.AdminSuperAdmin) {
		return errors.New("only superadmin can disable admins")
	}
	if status != "active" && status != "disabled" {
		return errors.New("bad status")
	}
	if adminID == ac.Admin.ID {
		return errors.New("cannot disable self")
	}
	if err := s.Store.Q().SetAdminStatus(ctx, adminID, status); err != nil {
		return err
	}
	if status == "disabled" {
		_ = s.Store.Q().RevokeAllSessions(ctx, adminID)
	}
	s.Audit(ctx, ac, "admin.status", "admin", adminID, nil, map[string]any{"status": status}, nil, ip, requestID)
	return nil
}

// ===== 封禁 =====

func (s *Services) CreateBan(ctx context.Context, ac *AdminContext, kind, value, reason string, until *time.Time, ip, requestID string) (*store.Ban, error) {
	if kind == "card_prefix" {
		// 检索值统一大写，与 NormalizeCard 输出一致
		value = strings.ToUpper(strings.TrimSpace(value))
	}
	switch kind {
	case "ip", "device", "card_prefix", "client_version", "asn":
	default:
		return nil, errors.New("bad ban kind")
	}
	b, err := s.Store.Q().CreateBan(ctx, kind, value, reason, ac.Admin.ID, until)
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, ac, "ban.create", "ban", b.ID, nil, b, nil, ip, requestID)
	return b, nil
}

func (s *Services) DeleteBan(ctx context.Context, ac *AdminContext, kind, value, ip, requestID string) error {
	if err := s.Store.Q().DeleteBan(ctx, kind, value); err != nil {
		return err
	}
	s.Audit(ctx, ac, "ban.delete", "ban", kind+":"+value, nil, nil, nil, ip, requestID)
	return nil
}

// ===== 统计（仪表盘） =====

type Stats struct {
	Products       int64            `json:"products"`
	Plans          int64            `json:"plans"`
	CardsByStatus  map[string]int64 `json:"cards_by_status"`
	ActiveLicenses int64            `json:"active_licenses"`
	OnlineNow      int64            `json:"online_now"` // 活跃租约（近似）
	Activations7d  int64            `json:"activations_7d"`
	RiskEvents24h  int64            `json:"risk_events_24h"`
	Agents         int64            `json:"agents"`
	Trend          []map[string]any `json:"trend"`
}

func (s *Services) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{CardsByStatus: map[string]int64{}}
	q := s.Store.Q()
	var err error
	if st.CardsByStatus, err = q.CountCardsByStatus(ctx); err != nil {
		return nil, err
	}
	if st.ActiveLicenses, err = q.CountLicensesByStatusSingle(ctx, "active"); err != nil {
		return nil, err
	}
	if st.Products, st.Plans, st.Agents, st.Activations7d, st.RiskEvents24h, err =
		q.CountMisc(ctx); err != nil {
		return nil, err
	}
	// 在线数：全部许可证在线集合大小近似（生产可由 Redis SCAN 聚合，此处采样核心指标）
	online, err := q.CountRecentHeartbeats(ctx, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	st.OnlineNow = online
	if st.Trend, err = q.DailyActivationTrend(ctx); err != nil {
		st.Trend = []map[string]any{}
	}
	return st, nil
}

// AgentScopeDenied 供 HTTP 层复用的 agent 数据范围判断（统一 404 语义）。
func AgentScopeDenied(ac *AdminContext, ownerAgentID *string) bool {
	return agentDenied(ac, ownerAgentID)
}

// autoSuffix 生成 8 位无歧义大写随机串（CSPRNG）。
func autoSuffix() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "ZZZZZZZZ"
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}

// SetCardNote 设置卡密备注（agent 角色只能改自己名下的卡）。
func (s *Services) SetCardNote(ctx context.Context, ac *AdminContext, cardID, note, ip, requestID string) error {
	card, err := s.Store.Q().GetCardByID(ctx, cardID)
	if err != nil {
		return err
	}
	if agentDenied(ac, card.AgentID) {
		return domain.ErrCardNotFound
	}
	if len(note) > 500 {
		return errors.New("note too long (max 500)")
	}
	if err := s.Store.Q().SetCardNote(ctx, cardID, strings.TrimSpace(note)); err != nil {
		return err
	}
	s.Audit(ctx, ac, "card.note", "card", card.ID, nil,
		map[string]any{"note": note}, nil, ip, requestID)
	return nil
}

// AdminExtendLicense 管理员手动延长许可证（配合事件与审计）。
func (s *Services) AdminExtendLicense(ctx context.Context, ac *AdminContext, licenseID string, days int, reason, ip, requestID string) (*time.Time, error) {
	if days <= 0 || days > 36500 {
		return nil, errors.New("days must be 1-36500")
	}
	lic, err := s.Store.Q().GetLicense(ctx, licenseID, false)
	if err != nil {
		return nil, err
	}
	if agentDenied(ac, lic.AgentID) {
		return nil, domain.ErrCardNotFound
	}
	if lic.Status == "revoked" || lic.Status == "voided" {
		return nil, domain.ErrLicenseRevoked
	}
	var newExp *time.Time
	err = s.Store.WithTx(ctx, func(q *store.Queries) error {
		var txErr error
		newExp, txErr = q.ExtendLicense(ctx, licenseID, days)
		if txErr != nil {
			return txErr
		}
		return q.InsertLicenseEvent(ctx, licenseID, "renewed", "admin:"+ac.Admin.ID, requestID,
			map[string]any{"reason": reason, "days": days})
	})
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, ac, "license.extend", "license", licenseID, nil,
		map[string]any{"days": days, "reason": reason, "new_expiry": newExp}, nil, ip, requestID)
	return newExp, nil
}

// findOrCreateCustomPlan 按产品+天数查找或创建自定义时长套餐（code 随机保证全局唯一）。
func (s *Services) findOrCreateCustomPlan(ctx context.Context, productID string, days int) (*store.Plan, error) {
	p, perr := s.Store.Q().GetPlanByProductDuration(ctx, productID, days)
	if perr == nil {
		return p, nil
	}
	if !errors.Is(perr, store.ErrNoRows) {
		return nil, perr
	}
	code := fmt.Sprintf("custom-%s-%dd", strings.ToLower(autoSuffix()), days)
	return s.Store.Q().CreatePlan(ctx, &store.Plan{
		ProductID:       productID,
		Code:            code,
		Name:            fmt.Sprintf("自定义 %d 天卡", days),
		Kind:            "duration",
		DurationDays:    days,
		DeviceLimit:     1,
		ConcurrentLimit: 1,
		Features:        []string{},
		HeartbeatSec:    60,
		LeaseTTL:        300,
		RebindCooldownH: 24,
		MonthlyRebind:   2,
	})
}
