package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Queries 汇集全部 SQL。既可绑定连接池（只读路径），也可绑定事务（写路径）。
type Queries struct {
	pool *pgxpool.Pool
	tx   pgx.Tx
}

// WithTx 在事务中执行 fn；fn 返回错误则回滚。
func (s *Store) WithTx(ctx context.Context, fn func(q *Queries) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	q := &Queries{pool: s.Pool, tx: tx}
	if err := fn(q); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// Q 返回池绑定（非事务）查询器。
func (s *Store) Q() *Queries { return &Queries{pool: s.Pool} }

func (q *Queries) exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if q.tx != nil {
		return q.tx.Exec(ctx, sql, args...)
	}
	return q.pool.Exec(ctx, sql, args...)
}

func (q *Queries) query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if q.tx != nil {
		return q.tx.Query(ctx, sql, args...)
	}
	return q.pool.Query(ctx, sql, args...)
}

func (q *Queries) queryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if q.tx != nil {
		return q.tx.QueryRow(ctx, sql, args...)
	}
	return q.pool.QueryRow(ctx, sql, args...)
}

// ===== 产品 =====

func (q *Queries) CreateProduct(ctx context.Context, code, name string) (*Product, error) {
	row, rerr := q.query(ctx,
		`INSERT INTO products(code,name) VALUES($1,$2) RETURNING id,code,name,status,created_at`, code, name)
	return collectOne[Product](row, rerr)
}

func (q *Queries) ListProducts(ctx context.Context) ([]*Product, error) {
	return collect[Product](q.query(ctx,
		`SELECT id,code,name,status,created_at FROM products ORDER BY created_at`))
}

func (q *Queries) GetProductByCode(ctx context.Context, code string) (*Product, error) {
	return collectOne[Product](q.query(ctx,
		`SELECT id,code,name,status,created_at FROM products WHERE code=$1`, code))
}

func (q *Queries) GetProduct(ctx context.Context, id string) (*Product, error) {
	return collectOne[Product](q.query(ctx,
		`SELECT id,code,name,status,created_at FROM products WHERE id=$1`, id))
}

func (q *Queries) SetProductStatus(ctx context.Context, id, status string) error {
	_, err := q.exec(ctx, `UPDATE products SET status=$2 WHERE id=$1`, id, status)
	return err
}

// ===== 套餐 =====

func (q *Queries) CreatePlan(ctx context.Context, p *Plan) (*Plan, error) {
	feats, _ := json.Marshal(p.Features)
	row, rerr := q.query(ctx, `
		INSERT INTO plans(product_id,code,name,kind,duration_days,fixed_expiry_days,uses_total,
			device_limit,concurrent_limit,features,offline_grace_seconds,lease_ttl_seconds,
			heartbeat_interval_seconds,rebind_cooldown_hours,monthly_rebind_limit,min_client_version,price_cents)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		RETURNING id,product_id,code,name,kind,duration_days,fixed_expiry_days,uses_total,
			device_limit,concurrent_limit,features,offline_grace_seconds,lease_ttl_seconds,
			heartbeat_interval_seconds,rebind_cooldown_hours,monthly_rebind_limit,min_client_version,
			price_cents,status,created_at`,
		p.ProductID, p.Code, p.Name, p.Kind, p.DurationDays, p.FixedExpiryDays, p.UsesTotal,
		p.DeviceLimit, p.ConcurrentLimit, feats, p.OfflineGrace, p.LeaseTTL,
		p.HeartbeatSec, p.RebindCooldownH, p.MonthlyRebind, p.MinClientVer, p.PriceCents)
	return collectOne[Plan](row, rerr)
}

func (q *Queries) ListPlans(ctx context.Context, productID string) ([]*Plan, error) {
	if productID != "" {
		return collect[Plan](q.query(ctx, planSelect+` WHERE product_id=$1 ORDER BY created_at`, productID))
	}
	return collect[Plan](q.query(ctx, planSelect+` ORDER BY created_at`))
}

func (q *Queries) SetPlanStatus(ctx context.Context, id, status string) error {
	tag, err := q.exec(ctx, `UPDATE plans SET status=$2 WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}
func (q *Queries) GetPlan(ctx context.Context, id string) (*Plan, error) {
	return collectOne[Plan](q.query(ctx, planSelect+` WHERE id=$1`, id))
}

func (q *Queries) UpdatePlan(ctx context.Context, p *Plan) (*Plan, error) {
	feats, _ := json.Marshal(p.Features)
	row, rerr := q.query(ctx, `UPDATE plans SET name=$2,duration_days=$3,fixed_expiry_days=$4,uses_total=$5,
		device_limit=$6,concurrent_limit=$7,features=$8,offline_grace_seconds=$9,lease_ttl_seconds=$10,
		heartbeat_interval_seconds=$11,rebind_cooldown_hours=$12,monthly_rebind_limit=$13,min_client_version=$14,price_cents=$15
		WHERE id=$1
		RETURNING id,product_id,code,name,kind,duration_days,fixed_expiry_days,uses_total,
			device_limit,concurrent_limit,features,offline_grace_seconds,lease_ttl_seconds,
			heartbeat_interval_seconds,rebind_cooldown_hours,monthly_rebind_limit,min_client_version,
			price_cents,status,created_at`, p.ID, p.Name, p.DurationDays, p.FixedExpiryDays, p.UsesTotal,
		p.DeviceLimit, p.ConcurrentLimit, feats, p.OfflineGrace, p.LeaseTTL, p.HeartbeatSec,
		p.RebindCooldownH, p.MonthlyRebind, p.MinClientVer, p.PriceCents)
	return collectOne[Plan](row, rerr)
}

func (q *Queries) CountPlanReferences(ctx context.Context, planID string) (int64, error) {
	var n int64
	err := q.queryRow(ctx, `SELECT (SELECT count(*) FROM card_batches WHERE plan_id=$1) +
		(SELECT count(*) FROM cards WHERE plan_id=$1) + (SELECT count(*) FROM licenses WHERE plan_id=$1)`, planID).Scan(&n)
	return n, err
}

// CountPlanLicenses 该套餐关联的许可证数（激活历史，删除套餐时不可清理）。
func (q *Queries) CountPlanLicenses(ctx context.Context, planID string) (int64, error) {
	var n int64
	err := q.queryRow(ctx, `SELECT count(*) FROM licenses WHERE plan_id=$1`, planID).Scan(&n)
	return n, err
}

// CountPlanLiveCards 该套餐下非"未使用"的卡数（激活/冻结/吊销等历史，删除时不可清理）。
func (q *Queries) CountPlanLiveCards(ctx context.Context, planID string) (int64, error) {
	var n int64
	err := q.queryRow(ctx, `SELECT count(*) FROM cards WHERE plan_id=$1 AND status <> 'unused'`, planID).Scan(&n)
	return n, err
}

// VoidAndDeleteUnusedCards 作废并删除套餐下全部未使用卡（从未流通，可安全清理）。
func (q *Queries) VoidAndDeleteUnusedCards(ctx context.Context, planID string) error {
	_, err := q.exec(ctx, `DELETE FROM cards WHERE plan_id=$1 AND status='unused'`, planID)
	return err
}

// DeleteBatchesByPlan 删除套餐下的制卡批次记录（调用前须先清理其卡密）。
func (q *Queries) DeleteBatchesByPlan(ctx context.Context, planID string) error {
	_, err := q.exec(ctx, `DELETE FROM card_batches WHERE plan_id=$1`, planID)
	return err
}

func (q *Queries) DeletePlan(ctx context.Context, planID string) error {
	tag, err := q.exec(ctx, `DELETE FROM plans WHERE id=$1`, planID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

// TouchLicensesPolicy 版本化策略变更：该套餐全部许可证 policy_version+1，
// 促使在线客户端在下个心跳拿到新策略（吊销/冻结/降配传播）。
func (q *Queries) TouchLicensesPolicy(ctx context.Context, planID string) error {
	_, err := q.exec(ctx,
		`UPDATE licenses SET policy_version=policy_version+1, updated_at=now() WHERE plan_id=$1`, planID)
	return err
}

const planSelect = `SELECT id,product_id,code,name,kind,duration_days,fixed_expiry_days,uses_total,
	device_limit,concurrent_limit,features,offline_grace_seconds,lease_ttl_seconds,
	heartbeat_interval_seconds,rebind_cooldown_hours,monthly_rebind_limit,min_client_version,
	price_cents,status,created_at FROM plans`

// ===== 代理商 =====

func (q *Queries) CreateAgent(ctx context.Context, name string, parentID *string) (*Agent, error) {
	row, rerr := q.query(ctx,
		`INSERT INTO agents(name,parent_id) VALUES($1,$2) RETURNING id,name,parent_id,balance_cents,status,created_at`,
		name, parentID)
	return collectOne[Agent](row, rerr)
}

func (q *Queries) ListAgents(ctx context.Context) ([]*Agent, error) {
	return collect[Agent](q.query(ctx,
		`SELECT id,name,parent_id,balance_cents,status,created_at FROM agents ORDER BY created_at`))
}

func (q *Queries) SetAgentStatus(ctx context.Context, id, status string) error {
	_, err := q.exec(ctx, `UPDATE agents SET status=$2 WHERE id=$1`, id, status)
	return err
}

// ===== 通用收集器 =====

// collectOne 单行收集：结构体走名字映射，原始类型（count 等）走 Scan。
func collectOne[T any](rows pgx.Rows, err error) (*T, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var v T
	rt := reflect.TypeOf(v)
	if rt != nil && rt.Kind() == reflect.Struct && rt != reflect.TypeOf(time.Time{}) {
		out, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByNameLax[T])
		if err != nil {
			return nil, NotFound(err)
		}
		return out, nil
	}
	val, err := pgx.CollectOneRow(rows, pgx.RowTo[T])
	if err != nil {
		return nil, NotFound(err)
	}
	return &val, nil
}

func collect[T any](rows pgx.Rows, err error) ([]*T, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByNameLax[T])
	if out == nil {
		out = []*T{} // 零行返回空切片而非 nil（JSON 序列化为 [] 而非 null）
	}
	return out, err
}

// ===== 代理余额 =====

func (q *Queries) GetAgent(ctx context.Context, id string) (*Agent, error) {
	return collectOne[Agent](q.query(ctx,
		`SELECT id,name,parent_id,balance_cents,status,created_at FROM agents WHERE id=$1`, id))
}

// DeductAgentBalance 原子扣款（余额充足才成功），返回扣款后余额。
func (q *Queries) DeductAgentBalance(ctx context.Context, agentID string, amountCents int64) (int64, error) {
	if amountCents <= 0 {
		return 0, fmt.Errorf("invalid deduction amount")
	}
	var after int64
	err := q.queryRow(ctx,
		`UPDATE agents SET balance_cents = balance_cents - $2
		 WHERE id=$1 AND balance_cents >= $2 RETURNING balance_cents`,
		agentID, amountCents).Scan(&after)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNoRows
	}
	return after, err
}

// TopUpAgentBalance 原子入账（amount 可为负做调差，CHECK 保证不为负），返回交易后余额。
func (q *Queries) TopUpAgentBalance(ctx context.Context, agentID string, amountCents int64) (int64, error) {
	var after int64
	err := q.queryRow(ctx,
		`UPDATE agents SET balance_cents = balance_cents + $2
		 WHERE id=$1 AND balance_cents + $2 >= 0 RETURNING balance_cents`,
		agentID, amountCents).Scan(&after)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNoRows
	}
	return after, err
}

func (q *Queries) InsertAgentTransaction(ctx context.Context, agentID string, amountCents, balanceAfter int64, kind string, refBatchID *string, note *string, createdBy *string) error {
	_, err := q.exec(ctx, `
		INSERT INTO agent_transactions(agent_id,amount_cents,balance_after,kind,ref_batch_id,note,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, agentID, amountCents, balanceAfter, kind, refBatchID, note, createdBy)
	return err
}

func (q *Queries) ListAgentTransactions(ctx context.Context, agentID string, limit int) ([]*AgentTransaction, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect[AgentTransaction](q.query(ctx,
		`SELECT id,agent_id,amount_cents,balance_after,kind,ref_batch_id,note,created_by,created_at
		 FROM agent_transactions WHERE agent_id=$1 ORDER BY created_at DESC LIMIT $2`, agentID, limit))
}

// GetPlanByProductDuration 查找同产品同天数的自定义时长套餐。
func (q *Queries) GetPlanByProductDuration(ctx context.Context, productID string, days int) (*Plan, error) {
	return collectOne[Plan](q.query(ctx, planSelect+`
		WHERE product_id=$1 AND kind='duration' AND duration_days=$2 AND code LIKE 'custom-%'
		ORDER BY created_at LIMIT 1`, productID, days))
}
