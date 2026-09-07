package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ===== 卡密 =====

type CreateBatchResult struct {
	Batch *CardBatch
	Cards []*Card // 仅含 lookup/prefix/状态，明文卡密由服务层持有
}

// CreateBatch 事务插入批次与卡密行。
func (q *Queries) CreateBatch(ctx context.Context, b *CardBatch, lookups []CardSeed) (*CreateBatchResult, error) {
	batch, rerr := q.query(ctx, `
		INSERT INTO card_batches(agent_id,product_id,plan_id,quantity,prefix,note,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		RETURNING id,agent_id,product_id,plan_id,quantity,prefix,note,created_by,created_at`,
		b.AgentID, b.ProductID, b.PlanID, b.Quantity, b.Prefix, b.Note, b.CreatedBy)
	batchRow, err := collectOne[CardBatch](batch, rerr)
	if err != nil {
		return nil, err
	}
	cards := make([]*Card, 0, len(lookups))
	for _, seed := range lookups {
		c, rerr := q.query(ctx, `
			INSERT INTO cards(batch_id,agent_id,product_id,plan_id,lookup,prefix,kind,uses_total,uses_left,secret_ciphertext,secret_nonce,secret_key_version,created_by)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			RETURNING id,batch_id,agent_id,product_id,plan_id,lookup,prefix,kind,status,uses_total,uses_left,
				license_id,used_by_user,activated_at,expires_at,created_by,created_at`,
			batchRow.ID, b.AgentID, b.ProductID, b.PlanID, seed.Lookup, seed.Prefix, seed.Kind,
			seed.UsesTotal, seed.UsesLeft, seed.SecretCiphertext, seed.SecretNonce, seed.SecretKeyVersion, b.CreatedBy)
		card, err := collectOne[Card](c, rerr)
		if err != nil {
			return nil, err
		}
		cards = append(cards, card)
	}
	return &CreateBatchResult{Batch: batchRow, Cards: cards}, nil
}

// CardSeed 批量制卡行种子。
type CardSeed struct {
	Lookup           string
	Prefix           string
	Kind             string
	UsesTotal        int
	UsesLeft         int
	SecretCiphertext []byte
	SecretNonce      []byte
	SecretKeyVersion string
}

// GetCardByID 按 ID 取卡密。
func (q *Queries) GetCardByID(ctx context.Context, id string) (*Card, error) {
	return collectOne[Card](q.query(ctx,
		`SELECT id,batch_id,agent_id,product_id,plan_id,lookup,prefix,kind,status,uses_total,uses_left,
			license_id,used_by_user,activated_at,expires_at,created_by,created_at FROM cards WHERE id=$1`, id))
}

// GetCardByLookup 卡密检索（HMAC 值精确匹配，走唯一索引）。
func (q *Queries) GetCardByLookup(ctx context.Context, lookup string, forUpdate bool) (*Card, error) {
	sql := `SELECT id,batch_id,agent_id,product_id,plan_id,lookup,prefix,kind,status,uses_total,uses_left,
		license_id,used_by_user,activated_at,expires_at,created_by,created_at FROM cards WHERE lookup=$1`
	if forUpdate {
		sql += ` FOR UPDATE`
	}
	return collectOne[Card](q.query(ctx, sql, lookup))
}

type CardFilter struct {
	AgentID   string // 数据范围（agent 角色强制）
	Prefix    string
	BatchID   string
	Status    string
	Kind      string
	PlanID    string
	ProductID string
	Search    string // prefix/掩码模糊
	Limit     int
	Offset    int
}

func (q *Queries) ListCards(ctx context.Context, f CardFilter) ([]*Card, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if f.AgentID != "" {
		where += fmt.Sprintf(" AND c.agent_id=$%d", len(args)+1)
		args = append(args, f.AgentID)
	}
	if f.Prefix != "" {
		where += fmt.Sprintf(" AND c.prefix=$%d", len(args)+1)
		args = append(args, f.Prefix)
	}
	if f.BatchID != "" {
		where += fmt.Sprintf(" AND c.batch_id=$%d", len(args)+1)
		args = append(args, f.BatchID)
	}
	if f.Status != "" {
		where += fmt.Sprintf(" AND c.status=$%d", len(args)+1)
		args = append(args, f.Status)
	}
	if f.Kind != "" {
		where += fmt.Sprintf(" AND c.kind=$%d", len(args)+1)
		args = append(args, f.Kind)
	}
	if f.PlanID != "" {
		where += fmt.Sprintf(" AND c.plan_id=$%d", len(args)+1)
		args = append(args, f.PlanID)
	}
	if f.ProductID != "" {
		where += fmt.Sprintf(" AND c.product_id=$%d", len(args)+1)
		args = append(args, f.ProductID)
	}
	if f.Search != "" {
		where += fmt.Sprintf(" AND c.prefix LIKE $%d", len(args)+1)
		args = append(args, f.Search+"%")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	total, err := collectOne[int64](q.query(ctx, "SELECT count(*) FROM cards c "+where, args...))
	if err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	cards, err := collect[Card](q.query(ctx,
		`SELECT c.id,c.batch_id,c.agent_id,ag.name AS agent_name,c.product_id,c.plan_id,c.lookup,c.prefix,
				c.kind,p.kind AS plan_kind,p.duration_days,p.fixed_expiry_days,p.price_cents,c.status,c.uses_total,c.uses_left,c.license_id,c.used_by_user,c.activated_at,
				c.expires_at,c.created_by,c.note,c.created_at
				FROM cards c LEFT JOIN plans p ON p.id=c.plan_id LEFT JOIN agents ag ON ag.id = c.agent_id`+where+
			fmt.Sprintf(" ORDER BY c.created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...))
	if err != nil {
		return nil, 0, err
	}
	return cards, int(*total), nil
}

// SetCardStatus 兼容内部业务调用；新状态迁移优先使用带守卫的方法。
func (q *Queries) SetCardStatus(ctx context.Context, cardID, status string) error {
	tag, err := q.exec(ctx, `UPDATE cards SET status=$2 WHERE id=$1`, cardID, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

// TransitionCardStatus 带当前状态守卫的卡密状态迁移。
func (q *Queries) TransitionCardStatus(ctx context.Context, id, from, to string) error {
	tag, err := q.exec(ctx,
		`UPDATE cards SET status=$3 WHERE id=$1 AND status=$2`, id, from, to)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

// TransitionCardToTerminal 将非终态卡密原子迁移为吊销/作废。
func (q *Queries) TransitionCardToTerminal(ctx context.Context, id, to string) error {
	tag, err := q.exec(ctx,
		`UPDATE cards SET status=$2 WHERE id=$1 AND status NOT IN ('revoked','voided','depleted')`, id, to)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

// ===== 许可证 =====

const licenseSelect = `SELECT id,product_id,plan_id,agent_id,origin_card_id,status,uses_left,
	activated_at,expires_at,policy_version,note,created_at,updated_at FROM licenses`

func (q *Queries) GetLicense(ctx context.Context, id string, forUpdate bool) (*License, error) {
	sql := licenseSelect + ` WHERE id=$1`
	if forUpdate {
		sql += ` FOR UPDATE`
	}
	return collectOne[License](q.query(ctx, sql, id))
}

func (q *Queries) CreateLicense(ctx context.Context, l *License) (*License, error) {
	row, rerr := q.query(ctx, `
		INSERT INTO licenses(product_id,plan_id,agent_id,origin_card_id,status,uses_left,expires_at)
		VALUES($1,$2,$3,$4,'active',$5,$6)
		RETURNING id,product_id,plan_id,agent_id,origin_card_id,status,uses_left,
			activated_at,expires_at,policy_version,note,created_at,updated_at`,
		l.ProductID, l.PlanID, l.AgentID, l.OriginCardID, l.UsesLeft, l.ExpiresAt)
	return collectOne[License](row, rerr)
}

// TransitionLicense 带状态机守卫的转换：仅当当前状态为 from 时改为 to。
func (q *Queries) TransitionLicense(ctx context.Context, id, from, to string) error {
	tag, err := q.exec(ctx,
		`UPDATE licenses SET status=$3, updated_at=now() WHERE id=$1 AND status=$2`, id, from, to)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

func (q *Queries) TransitionLicenseTerminal(ctx context.Context, id, to string) error {
	tag, err := q.exec(ctx,
		`UPDATE licenses SET status=$2, updated_at=now() WHERE id=$1 AND status NOT IN ('revoked','voided')`, id, to)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

// ConsumeLicenseUse 次卡原子扣减（>0 守卫），返回剩余次数。
func (q *Queries) ConsumeLicenseUse(ctx context.Context, licenseID string) (int, error) {
	var left int
	err := q.queryRow(ctx,
		`UPDATE licenses SET uses_left = uses_left - 1 WHERE id=$1 AND uses_left > 0 RETURNING uses_left`,
		licenseID).Scan(&left)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNoRows
	}
	return left, err
}

// MarkExpiredLicenseEvents 为已到期许可证补记 expired 事件（幂等，事件表追加写）。
func (q *Queries) MarkExpiredLicenseEvents(ctx context.Context) (int64, error) {
	tag, err := q.exec(ctx, `
		INSERT INTO license_events(license_id, kind, actor, detail)
		SELECT l.id, 'expired', 'system', '{}'::jsonb FROM licenses l
		WHERE l.status='active' AND l.expires_at < now()
		  AND NOT EXISTS (SELECT 1 FROM license_events e WHERE e.license_id = l.id AND e.kind='expired')`)
	return tag.RowsAffected(), err
}

// ExtendLicense 续费：expires_at = GREATEST(now, expires_at) + days，返回新到期时间。
// 调用方在事务内先读旧行（FOR UPDATE）以获得旧值，防止并发续费丢失更新。
func (q *Queries) ExtendLicense(ctx context.Context, licenseID string, days int) (*time.Time, error) {
	row := q.queryRow(ctx, `
		UPDATE licenses SET
			expires_at = CASE
				WHEN expires_at IS NULL THEN now() + make_interval(days=>$2)
				WHEN expires_at < now() THEN now() + make_interval(days=>$2)
				ELSE expires_at + make_interval(days=>$2) END,
			updated_at = now()
		WHERE id=$1
		RETURNING expires_at`, licenseID, days)
	var newV *time.Time
	if err := row.Scan(&newV); err != nil {
		return nil, NotFound(err)
	}
	return newV, nil
}

func (q *Queries) SetLicenseNote(ctx context.Context, id, note string) error {
	_, err := q.exec(ctx, `UPDATE licenses SET note=$2, updated_at=now() WHERE id=$1`, id, note)
	return err
}

type LicenseFilter struct {
	AgentID string
	Status  string
	Product string
	Search  string // note/prefix 模糊（经 origin card prefix）
	Limit   int
	Offset  int
}

func (q *Queries) ListLicenses(ctx context.Context, f LicenseFilter) ([]*License, int, error) {
	where := "WHERE 1=1"
	args := []any{}
	if f.AgentID != "" {
		where += fmt.Sprintf(" AND l.agent_id=$%d", len(args)+1)
		args = append(args, f.AgentID)
	}
	if f.Status != "" {
		where += fmt.Sprintf(" AND l.status=$%d", len(args)+1)
		args = append(args, f.Status)
	}
	if f.Product != "" {
		where += fmt.Sprintf(" AND l.product_id=$%d", len(args)+1)
		args = append(args, f.Product)
	}
	if f.Search != "" {
		// 许可证 UUID 或源卡密前缀检索（cards.prefix 有索引）
		where += fmt.Sprintf(" AND (l.id::text LIKE $%d OR EXISTS (SELECT 1 FROM cards oc WHERE oc.id = l.origin_card_id AND oc.prefix LIKE $%d))",
			len(args)+1, len(args)+1)
		args = append(args, "%"+f.Search+"%")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	total, err := collectOne[int64](q.query(ctx,
		"SELECT count(*) FROM licenses l "+where, args...))
	if err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	lics, err := collect[License](q.query(ctx, licenseSelectQ+where+
		fmt.Sprintf(" ORDER BY l.created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...))
	if err != nil {
		return nil, 0, err
	}
	return lics, int(*total), nil
}

const licenseSelectQ = `SELECT l.id,l.product_id,l.plan_id,l.agent_id,l.origin_card_id,l.status,l.uses_left,
	l.activated_at,l.expires_at,l.policy_version,l.note,l.created_at,l.updated_at FROM licenses l `

// ===== 设备 =====

const deviceSelect = `SELECT id,license_id,fingerprint_hash,device_pub,pub_kty,trust_level,hw_snapshot,status,
	bound_at,unbound_at,unbound_by,last_heartbeat_at,last_ip::text AS last_ip,client_version,last_seq FROM devices`

func (q *Queries) CreateDevice(ctx context.Context, d *Device) (*Device, error) {
	row, rerr := q.query(ctx, `
		INSERT INTO devices(license_id,fingerprint_hash,device_pub,pub_kty,trust_level,hw_snapshot,client_version,last_ip)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id,license_id,fingerprint_hash,device_pub,pub_kty,trust_level,hw_snapshot,status,
			bound_at,unbound_at,unbound_by,last_heartbeat_at,last_ip::text AS last_ip,client_version,last_seq`,
		d.LicenseID, d.FingerprintHash, d.DevicePub, d.PubKty, d.TrustLevel, d.HwSnapshot, d.ClientVersion, d.LastIP)
	return collectOne[Device](row, rerr)
}

func (q *Queries) GetDeviceByFingerprint(ctx context.Context, licenseID, fpHash string) (*Device, error) {
	return collectOne[Device](q.query(ctx,
		deviceSelect+` WHERE license_id=$1 AND fingerprint_hash=$2`, licenseID, fpHash))
}

func (q *Queries) GetDeviceByPub(ctx context.Context, pub string) (*Device, error) {
	return collectOne[Device](q.query(ctx,
		deviceSelect+` WHERE device_pub=$1 AND status='active' ORDER BY bound_at DESC LIMIT 1`, pub))
}

func (q *Queries) GetDevice(ctx context.Context, id string) (*Device, error) {
	return collectOne[Device](q.query(ctx, deviceSelect+` WHERE id=$1`, id))
}

func (q *Queries) CountActiveDevices(ctx context.Context, licenseID string) (int, error) {
	n, err := collectOne[int64](q.query(ctx,
		`SELECT count(*) FROM devices WHERE license_id=$1 AND status='active'`, licenseID))
	if err != nil {
		return 0, err
	}
	return int(*n), nil
}

// UnbindDevice 解绑设备（管理员或自助下线）。返回被解绑设备（用于在线名额回收）。
func (q *Queries) UnbindDevice(ctx context.Context, deviceID, by string) (*Device, error) {
	row, rerr := q.query(ctx, `
		UPDATE devices SET status='unbound', unbound_at=now(), unbound_by=$2
		WHERE id=$1 AND status='active'
		RETURNING id,license_id,fingerprint_hash,device_pub,pub_kty,trust_level,hw_snapshot,status,
			bound_at,unbound_at,unbound_by,last_heartbeat_at,last_ip::text AS last_ip,client_version,last_seq`,
		deviceID, by)
	return collectOne[Device](row, rerr)
}

func (q *Queries) ListDevices(ctx context.Context, licenseID string, includeUnbound bool) ([]*Device, error) {
	sql := deviceSelect + ` WHERE license_id=$1`
	if !includeUnbound {
		sql += ` AND status='active'`
	}
	sql += ` ORDER BY bound_at`
	return collect[Device](q.query(ctx, sql, licenseID))
}

// BumpDeviceHeartbeat 心跳元数据 + 序列号（DB 为最终事实）。
func (q *Queries) BumpDeviceHeartbeat(ctx context.Context, deviceID string, seq int64, ip, version string) error {
	_, err := q.exec(ctx, `
		UPDATE devices SET last_heartbeat_at=now(), last_seq=GREATEST(last_seq,$2),
			last_ip=$3, client_version=COALESCE(NULLIF($4,''),client_version)
		WHERE id=$1`, deviceID, seq, ip, version)
	return err
}

// AcceptDeviceSeq 原子接受更大的设备序列号，供 Redis 故障时回退使用。
func (q *Queries) AcceptDeviceSeq(ctx context.Context, deviceID string, seq int64) (bool, error) {
	var accepted bool
	err := q.queryRow(ctx, `
		UPDATE devices SET last_seq=$2
		WHERE id=$1 AND last_seq < $2
		RETURNING true`, deviceID, seq).Scan(&accepted)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if e := q.queryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1)`, deviceID).Scan(&exists); e != nil {
			return false, e
		}
		if !exists {
			return false, ErrNoRows
		}
		return false, nil
	}
	return accepted, err
}

// SetCardActivated 激活落库：卡片转 active 并指向许可证。
func (q *Queries) SetCardActivated(ctx context.Context, cardID, licenseID string, at time.Time) error {
	_, err := q.exec(ctx, `UPDATE cards SET status=CASE WHEN status='depleted' THEN 'depleted' ELSE 'active' END, license_id=$2, activated_at=$3 WHERE id=$1 AND status IN ('unused','depleted')`, cardID, licenseID, at)
	return err
}

// RotateDevicePub 同机重装系统后轮换设备公钥（指纹不变）。
func (q *Queries) RotateDevicePub(ctx context.Context, deviceID, newPub, kty, trustLevel string) error {
	tag, err := q.exec(ctx, `
		UPDATE devices SET device_pub=$2, pub_kty=$3, trust_level=$4 WHERE id=$1 AND NOT EXISTS (
			SELECT 1 FROM devices d2 WHERE d2.device_pub=$2 AND d2.status='active' AND d2.id<>$1
		)`, deviceID, newPub, kty, trustLevel)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

// InsertRenewal 记录续费流水。
func (q *Queries) InsertRenewal(ctx context.Context, licenseID, cardID string, days int, oldExp, newExp *time.Time) error {
	_, err := q.exec(ctx, `
		INSERT INTO renewals(license_id,card_id,days_added,old_expires_at,new_expires_at)
		VALUES($1,$2,$3,$4,$5)`, licenseID, cardID, days, oldExp, newExp)
	return err
}

// InsertActivation 记录激活流水。
func (q *Queries) InsertActivation(ctx context.Context, licenseID, cardID, deviceID, kind, ip string) error {
	var ipArg any
	if ip != "" {
		ipArg = ip
	}
	_, err := q.exec(ctx, `
		INSERT INTO activations(license_id,card_id,device_id,kind,ip) VALUES($1,$2,$3,$4,$5)`,
		licenseID, cardID, deviceID, kind, ipArg)
	return err
}

// ===== 事件 =====

func (q *Queries) InsertLicenseEvent(ctx context.Context, licenseID, kind, actor, requestID string, detail map[string]any) error {
	b, _ := json.Marshal(detail)
	_, err := q.exec(ctx, `
		INSERT INTO license_events(license_id,kind,actor,detail,request_id)
		VALUES($1,$2,$3,$4,$5)`, licenseID, kind, actor, b, requestID)
	return err
}

func (q *Queries) ListLicenseEvents(ctx context.Context, licenseID string, limit int) ([]map[string]any, error) {
	rows, err := q.query(ctx, `
		SELECT id,kind,actor,detail,request_id,created_at
		FROM license_events WHERE license_id=$1 ORDER BY created_at DESC LIMIT $2`,
		licenseID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var kind, actor string
		var detail []byte
		var requestID *string
		var ts time.Time
		if err := rows.Scan(&id, &kind, &actor, &detail, &requestID, &ts); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "kind": kind, "actor": actor, "detail": json.RawMessage(detail),
			"request_id": requestID, "created_at": ts,
		})
	}
	return out, rows.Err()
}

// SetCardNote 设置卡密备注（管理员可编辑的唯一卡密信息）。
func (q *Queries) SetCardNote(ctx context.Context, cardID, note string) error {
	_, err := q.exec(ctx, `UPDATE cards SET note=$2 WHERE id=$1`, cardID, note)
	return err
}

// GetPlanByCode 按代码查套餐（自定义时长套餐复用判定）。
func (q *Queries) GetPlanByCode(ctx context.Context, code string) (*Plan, error) {
	return collectOne[Plan](q.query(ctx, planSelect+` WHERE code=$1`, code))
}
