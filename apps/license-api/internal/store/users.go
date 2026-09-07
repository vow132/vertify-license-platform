package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ===== 终端用户账号 =====

type EndUser struct {
	ID             string     `json:"id" db:"id"`
	ProductID      string     `json:"product_id" db:"product_id"`
	Username       string     `json:"username" db:"username"`
	PasswordHash   string     `json:"-" db:"password_hash"`
	SecurityHash   string     `json:"-" db:"security_hash"`
	Status         string     `json:"status" db:"status"`
	ExpiresAt      time.Time  `json:"expires_at" db:"expires_at"`
	MachineHash    *string    `json:"-" db:"machine_hash"`
	MachineBoundAt *time.Time `json:"machine_bound_at" db:"machine_bound_at"`
	RegIP          *string    `json:"reg_ip" db:"reg_ip"`
	LastLoginAt    *time.Time `json:"last_login_at" db:"last_login_at"`
	LastIP         *string    `json:"last_ip" db:"last_ip"`
	Note           *string    `json:"note" db:"note"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

const endUserSelect = `SELECT id,product_id,username,password_hash,security_hash,status,expires_at,
	machine_hash,machine_bound_at,reg_ip::text AS reg_ip,last_login_at,last_ip::text AS last_ip,note,
	created_at,updated_at FROM end_users`

func (q *Queries) CreateEndUser(ctx context.Context, u *EndUser) (*EndUser, error) {
	row, rerr := q.query(ctx, `
		INSERT INTO end_users(product_id,username,password_hash,security_hash,expires_at,reg_ip)
		VALUES($1,$2,$3,$4,$5,$6)
		RETURNING id,product_id,username,password_hash,security_hash,status,expires_at,
			machine_hash,machine_bound_at,reg_ip::text AS reg_ip,last_login_at,last_ip::text AS last_ip,note,
			created_at,updated_at`,
		u.ProductID, u.Username, u.PasswordHash, u.SecurityHash, u.ExpiresAt, nullableIP(u.RegIP))
	return collectOne[EndUser](row, rerr)
}

func (q *Queries) GetEndUser(ctx context.Context, id string) (*EndUser, error) {
	return collectOne[EndUser](q.query(ctx, endUserSelect+` WHERE id=$1`, id))
}

func (q *Queries) GetEndUserByName(ctx context.Context, productID, username string) (*EndUser, error) {
	return collectOne[EndUser](q.query(ctx, endUserSelect+` WHERE product_id=$1 AND username=$2`, productID, username))
}

func nullableIP(ip *string) any {
	if ip == nil || *ip == "" {
		return nil
	}
	return *ip
}

// ExtendEndUser 账号续期：GREATEST(now, expires_at) + days。
func (q *Queries) ExtendEndUser(ctx context.Context, userID string, days int) (*time.Time, error) {
	var newExp *time.Time
	err := q.queryRow(ctx, `
		UPDATE end_users SET
			expires_at = CASE WHEN expires_at < now() THEN now() + make_interval(days=>$2)
			                  ELSE expires_at + make_interval(days=>$2) END,
			updated_at = now()
		WHERE id=$1 RETURNING expires_at`, userID, days).Scan(&newExp)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoRows
	}
	return newExp, err
}

// BindEndUserMachine 首次登录绑定机器（machine_hash 为空时绑定成功）。
func (q *Queries) BindEndUserMachine(ctx context.Context, userID, machineHash string) error {
	tag, err := q.exec(ctx,
		`UPDATE end_users SET machine_hash=$2, machine_bound_at=now() WHERE id=$1 AND machine_hash IS NULL`,
		userID, machineHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

// ResetEndUserMachine 管理员解绑机器。
func (q *Queries) ResetEndUserMachine(ctx context.Context, userID string) error {
	_, err := q.exec(ctx,
		`UPDATE end_users SET machine_hash=NULL, machine_bound_at=NULL WHERE id=$1`, userID)
	return err
}

func (q *Queries) SetEndUserPassword(ctx context.Context, userID, hash string) error {
	_, err := q.exec(ctx,
		`UPDATE end_users SET password_hash=$2, updated_at=now() WHERE id=$1`, userID, hash)
	return err
}

func (q *Queries) SetEndUserStatus(ctx context.Context, userID, status string) error {
	_, err := q.exec(ctx, `UPDATE end_users SET status=$2, updated_at=now() WHERE id=$1`, userID, status)
	return err
}

func (q *Queries) SetEndUserNote(ctx context.Context, userID, note string) error {
	_, err := q.exec(ctx, `UPDATE end_users SET note=$2, updated_at=now() WHERE id=$1`, userID, note)
	return err
}

// MarkCardUsedByUser 卡密绑定到账号（与许可证激活互斥消耗）。
func (q *Queries) MarkCardUsedByUser(ctx context.Context, cardID, userID string) error {
	tag, err := q.exec(ctx,
		`UPDATE cards SET used_by_user=$2, status='depleted', activated_at=now()
		 WHERE id=$1 AND status='unused' AND license_id IS NULL AND used_by_user IS NULL`,
		cardID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRows
	}
	return nil
}

type EndUserFilter struct {
	ProductID string
	Status    string
	Search    string // 用户名模糊
	Limit     int
	Offset    int
}

func (q *Queries) ListEndUsers(ctx context.Context, f EndUserFilter) ([]*EndUser, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if f.ProductID != "" {
		where += fmt.Sprintf(" AND product_id=$%d", len(args)+1)
		args = append(args, f.ProductID)
	}
	if f.Status != "" {
		where += fmt.Sprintf(" AND status=$%d", len(args)+1)
		args = append(args, f.Status)
	}
	if f.Search != "" {
		where += fmt.Sprintf(" AND username LIKE $%d", len(args)+1)
		args = append(args, f.Search+"%")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	total, err := collectOne[int64](q.query(ctx, "SELECT count(*) FROM end_users "+where, args...))
	if err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	users, err := collect[EndUser](q.query(ctx, endUserSelect+where+
		fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...))
	if err != nil {
		return nil, 0, err
	}
	return users, int(*total), nil
}

// ===== 用户日志 =====

func (q *Queries) InsertEndUserLog(ctx context.Context, userID *string, username, kind string, productID *string, ip *string, detail map[string]any) error {
	b, _ := json.Marshal(detail)
	_, err := q.exec(ctx, `
		INSERT INTO end_user_logs(user_id,username,product_id,kind,ip,detail)
		VALUES($1,$2,$3,$4,$5,$6)`, userID, username, productID, kind, nullableIP(ip), b)
	return err
}

type EndUserLog struct {
	ID        int64     `json:"id" db:"id"`
	UserID    *string   `json:"user_id" db:"user_id"`
	Username  string    `json:"username" db:"username"`
	ProductID *string   `json:"product_id" db:"product_id"`
	Kind      string    `json:"kind" db:"kind"`
	IP        *string   `json:"ip" db:"ip"`
	Detail    []byte    `json:"detail" db:"detail"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

func (q *Queries) ListEndUserLogs(ctx context.Context, userID string, limit int) ([]*EndUserLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect[EndUserLog](q.query(ctx, `
		SELECT id,user_id,username,product_id,kind,ip::text AS ip,detail,created_at
		FROM end_user_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`, userID, limit))
}

func (q *Queries) ListRecentUserLogs(ctx context.Context, limit int) ([]*EndUserLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect[EndUserLog](q.query(ctx, `
		SELECT id,user_id,username,product_id,kind,ip::text AS ip,detail,created_at
		FROM end_user_logs ORDER BY created_at DESC LIMIT $1`, limit))
}

// ===== 软件公告 =====

func (q *Queries) CreateSoftMessage(ctx context.Context, productID, content, createdBy string) (*map[string]any, error) {
	row := q.queryRow(ctx, `
		INSERT INTO soft_messages(product_id,content,created_by) VALUES($1,$2,$3)
		RETURNING id, product_id::text, content, enabled, created_at`, productID, content, createdBy)
	var id int64
	var pid, content2 string
	var enabled bool
	var ts time.Time
	if err := row.Scan(&id, &pid, &content2, &enabled, &ts); err != nil {
		return nil, err
	}
	return &map[string]any{"id": id, "product_id": pid, "content": content2, "enabled": enabled, "created_at": ts}, nil
}

func (q *Queries) SetSoftMessageEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := q.exec(ctx, `UPDATE soft_messages SET enabled=$2 WHERE id=$1`, id, enabled)
	return err
}

func (q *Queries) DeleteSoftMessage(ctx context.Context, id int64) error {
	_, err := q.exec(ctx, `DELETE FROM soft_messages WHERE id=$1`, id)
	return err
}

func (q *Queries) ListSoftMessages(ctx context.Context, productID string) ([]map[string]any, error) {
	rows, err := q.query(ctx, `
		SELECT id, product_id::text, content, enabled, created_at
		FROM soft_messages WHERE ($1='' OR product_id::text=$1)
		ORDER BY created_at DESC LIMIT 200`, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var pid, content string
		var enabled bool
		var ts time.Time
		if err := rows.Scan(&id, &pid, &content, &enabled, &ts); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "product_id": pid, "content": content, "enabled": enabled, "created_at": ts})
	}
	return out, rows.Err()
}

// LatestEnabledMessage 产品当前生效公告。
func (q *Queries) LatestEnabledMessage(ctx context.Context, productID string) (string, error) {
	var content string
	err := q.queryRow(ctx, `
		SELECT content FROM soft_messages
		WHERE product_id=$1 AND enabled=true ORDER BY created_at DESC LIMIT 1`, productID).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return content, err
}

// ===== 软件版本 =====

func (q *Queries) CreateProductVersion(ctx context.Context, productID, version, downloadURL, notes string, force bool) (*ProductVersion, error) {
	row, rerr := q.query(ctx, `
		INSERT INTO product_versions(product_id,version,download_url,notes,force_update)
		VALUES($1,$2,$3,$4,$5)
		RETURNING id,product_id::text AS product_id,version,download_url,notes,force_update,created_at`,
		productID, version, downloadURL, notes, force)
	return collectOne[ProductVersion](row, rerr)
}

func (q *Queries) DeleteProductVersion(ctx context.Context, id int64) error {
	_, err := q.exec(ctx, `DELETE FROM product_versions WHERE id=$1`, id)
	return err
}

func (q *Queries) ListProductVersions(ctx context.Context, productID string) ([]*ProductVersion, error) {
	return collect[ProductVersion](q.query(ctx, `
		SELECT id,product_id::text AS product_id,version,download_url,notes,force_update,created_at
		FROM product_versions WHERE ($1='' OR product_id::text=$1)
		ORDER BY created_at DESC LIMIT 200`, productID))
}

// LatestProductVersion 产品最新版本（发布时间倒序第一）。
func (q *Queries) LatestProductVersion(ctx context.Context, productID string) (*ProductVersion, error) {
	return collectOne[ProductVersion](q.query(ctx, `
		SELECT id,product_id::text AS product_id,version,download_url,notes,force_update,created_at
		FROM product_versions WHERE product_id=$1 ORDER BY created_at DESC LIMIT 1`, productID))
}

type ProductVersion struct {
	ID          int64     `json:"id" db:"id"`
	ProductID   string    `json:"product_id" db:"product_id"`
	Version     string    `json:"version" db:"version"`
	DownloadURL string    `json:"download_url" db:"download_url"`
	Notes       *string   `json:"notes" db:"notes"`
	ForceUpdate bool      `json:"force_update" db:"force_update"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// ===== 接口级限流配置 =====

func (q *Queries) UpsertApiRateLimit(ctx context.Context, scope string, limitPerMin int) error {
	_, err := q.exec(ctx, `
		INSERT INTO api_rate_limits(scope,limit_per_min) VALUES($1,$2)
		ON CONFLICT (scope) DO UPDATE SET limit_per_min=EXCLUDED.limit_per_min, updated_at=now()`,
		scope, limitPerMin)
	return err
}

func (q *Queries) ListApiRateLimits(ctx context.Context) ([]map[string]any, error) {
	rows, err := q.query(ctx, `SELECT scope,limit_per_min,updated_at FROM api_rate_limits ORDER BY scope`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var scope string
		var lim int
		var ts time.Time
		if err := rows.Scan(&scope, &lim, &ts); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"scope": scope, "limit_per_min": lim, "updated_at": ts})
	}
	return out, rows.Err()
}

// AllApiRateLimits 返回 scope→limit 映射（中间件 30s 缓存用）。
func (q *Queries) AllApiRateLimits(ctx context.Context) (map[string]int, error) {
	rows, err := q.query(ctx, `SELECT scope,limit_per_min FROM api_rate_limits`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var scope string
		var lim int
		if err := rows.Scan(&scope, &lim); err != nil {
			return nil, err
		}
		out[scope] = lim
	}
	return out, rows.Err()
}

// TouchEndUserLogin 更新登录时间与 IP。
func (q *Queries) TouchEndUserLogin(ctx context.Context, userID string, ip string) error {
	var ipArg any
	if ip != "" {
		ipArg = ip
	}
	_, err := q.exec(ctx,
		`UPDATE end_users SET last_login_at=now(), last_ip=$2 WHERE id=$1`, userID, ipArg)
	return err
}

// DailyActivationTrend 近 7 天每日激活数量（仪表盘趋势图）。
func (q *Queries) DailyActivationTrend(ctx context.Context) ([]map[string]any, error) {
	rows, err := q.query(ctx, `
		SELECT d::date::text AS day, COALESCE(c.cnt, 0) AS count
		FROM generate_series(now()::date - 6, now()::date, '1 day') d
		LEFT JOIN (
			SELECT created_at::date AS day, count(*) AS cnt
			FROM activations WHERE created_at > now() - interval '7 days'
			GROUP BY day
		) c ON c.day = d::date
		ORDER BY d`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var day string
		var cnt int64
		if err := rows.Scan(&day, &cnt); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"day": day, "count": cnt})
	}
	return out, rows.Err()
}
