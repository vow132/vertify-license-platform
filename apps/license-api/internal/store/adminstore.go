package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ===== 管理员 =====

const adminSelect = `SELECT id,username,password_hash,display_name,role,agent_id,totp_secret,
	mfa_enabled,status,failed_attempts,locked_until,must_change_password,created_at,last_login_at FROM admins`

func (q *Queries) GetAdminByUsername(ctx context.Context, username string) (*Admin, error) {
	return collectOne[Admin](q.query(ctx, adminSelect+` WHERE username=$1`, username))
}

func (q *Queries) GetAdmin(ctx context.Context, id string) (*Admin, error) {
	return collectOne[Admin](q.query(ctx, adminSelect+` WHERE id=$1`, id))
}

func (q *Queries) CreateAdmin(ctx context.Context, a *Admin) (*Admin, error) {
	row, rerr := q.query(ctx, `
		INSERT INTO admins(username,password_hash,display_name,role,agent_id,totp_secret,mfa_enabled,must_change_password)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id,username,password_hash,display_name,role,agent_id,totp_secret,mfa_enabled,
			status,failed_attempts,locked_until,must_change_password,created_at,last_login_at`,
		a.Username, a.PasswordHash, a.DisplayName, a.Role, a.AgentID, a.TOTPSecret, a.MFAEnabled, a.MustChangePassword)
	return collectOne[Admin](row, rerr)
}

func (q *Queries) CountAdmins(ctx context.Context) (int, error) {
	n, err := collectOne[int64](q.query(ctx, `SELECT count(*) FROM admins`))
	if err != nil {
		return 0, err
	}
	return int(*n), nil
}

func (q *Queries) ListAdmins(ctx context.Context) ([]*Admin, error) {
	return collect[Admin](q.query(ctx, adminSelect+` ORDER BY created_at`))
}

// OnLoginSuccess 重置失败计数并记录登录时间。
func (q *Queries) OnLoginSuccess(ctx context.Context, adminID string) error {
	_, err := q.exec(ctx, `
		UPDATE admins SET failed_attempts=0, locked_until=NULL, last_login_at=now() WHERE id=$1`, adminID)
	return err
}

// OnLoginFailed 失败计数 +1，达到阈值则锁定 15 分钟（防在线爆破）。
func (q *Queries) OnLoginFailed(ctx context.Context, adminID string) (locked bool, err error) {
	err = q.queryRow(ctx, `
		UPDATE admins SET failed_attempts=failed_attempts+1,
			locked_until = CASE WHEN failed_attempts+1 >= 5 THEN now() + interval '15 minutes' END
		WHERE id=$1
		RETURNING locked_until IS NOT NULL AND locked_until > now()`, adminID).Scan(&locked)
	return locked, err
}

func (q *Queries) SetAdminMFA(ctx context.Context, adminID string, secret *string, enabled bool) error {
	_, err := q.exec(ctx,
		`UPDATE admins SET totp_secret=$2, mfa_enabled=$3 WHERE id=$1`, adminID, secret, enabled)
	return err
}

func (q *Queries) SetAdminPassword(ctx context.Context, adminID, hash string, mustChange bool) error {
	_, err := q.exec(ctx, `
		UPDATE admins SET password_hash=$2, must_change_password=$3, failed_attempts=0, locked_until=NULL
		WHERE id=$1`, adminID, hash, mustChange)
	return err
}

func (q *Queries) SetAdminStatus(ctx context.Context, adminID, status string) error {
	_, err := q.exec(ctx, `UPDATE admins SET status=$2 WHERE id=$1`, adminID, status)
	return err
}

// ===== 后台会话 =====

func (q *Queries) CreateSession(ctx context.Context, s *AdminSession, ip, ua string) error {
	var ipArg any
	if ip != "" {
		ipArg = ip // 空字符串传 NULL，INET 类型不接受 ''
	}
	_, err := q.exec(ctx, `
		INSERT INTO admin_sessions(id,admin_id,token_hash,csrf_token,mfa_passed,ip,user_agent,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		s.ID, s.AdminID, s.TokenHash, s.CSRFToken, s.MFAPassed, ipArg, ua, s.ExpiresAt)
	return err
}

// GetSessionByTokenHash 会话查找（token 明文只存 cookie，库存 SHA-256）。
func (q *Queries) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*AdminSession, error) {
	row := q.queryRow(ctx, `
		SELECT id,admin_id,token_hash,csrf_token,mfa_passed,expires_at
		FROM admin_sessions
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > now()`, tokenHash)
	var s AdminSession
	err := row.Scan(&s.ID, &s.AdminID, &s.TokenHash, &s.CSRFToken, &s.MFAPassed, &s.ExpiresAt)
	if err != nil {
		return nil, NotFound(err)
	}
	return &s, nil
}

func (q *Queries) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := q.exec(ctx, `UPDATE admin_sessions SET revoked_at=now() WHERE id=$1`, sessionID)
	return err
}

func (q *Queries) RevokeAllSessions(ctx context.Context, adminID string) error {
	_, err := q.exec(ctx,
		`UPDATE admin_sessions SET revoked_at=now() WHERE admin_id=$1 AND revoked_at IS NULL`, adminID)
	return err
}

// GetAgentAdmin 取代理商的登录账号（role=agent 且绑定该代理）。
func (q *Queries) GetAgentAdmin(ctx context.Context, agentID string) (*Admin, error) {
	return collectOne[Admin](q.query(ctx, adminSelect+` WHERE role='agent' AND agent_id=$1 AND status='active' ORDER BY created_at LIMIT 1`, agentID))
}

// ReapSessions 清理过期会话（worker 调用），返回清理数量。
func (q *Queries) ReapSessions(ctx context.Context) (int64, error) {
	tag, err := q.exec(ctx, `DELETE FROM admin_sessions WHERE expires_at < now() - interval '7 days'`)
	return tag.RowsAffected(), err
}

// ===== 审计 =====

func (q *Queries) InsertAudit(ctx context.Context, a *AuditLog) error {
	var ipArg any
	if a.IP != nil && *a.IP != "" {
		ipArg = *a.IP
	}
	_, err := q.exec(ctx, `
		INSERT INTO audit_logs(admin_id,admin_username,action,target_type,target_id,
			before_state,after_state,detail,ip,request_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		a.AdminID, a.AdminUsername, a.Action, a.TargetType, a.TargetID,
		a.BeforeState, a.AfterState, a.Detail, ipArg, a.RequestID)
	return err
}

type AuditFilter struct {
	AdminID string
	Action  string
	Target  string
	Since   *time.Time
	Until   *time.Time
	Limit   int
	Offset  int
}

func (q *Queries) ListAudit(ctx context.Context, f AuditFilter) ([]*AuditLog, int, error) {
	where := "WHERE 1=1"
	args := []any{}
	if f.AdminID != "" {
		where += fmt.Sprintf(" AND admin_id=$%d", len(args)+1)
		args = append(args, f.AdminID)
	}
	if f.Action != "" {
		where += fmt.Sprintf(" AND action=$%d", len(args)+1)
		args = append(args, f.Action)
	}
	if f.Target != "" {
		where += fmt.Sprintf(" AND target_id=$%d", len(args)+1)
		args = append(args, f.Target)
	}
	if f.Since != nil {
		where += fmt.Sprintf(" AND ts >= $%d", len(args)+1)
		args = append(args, *f.Since)
	}
	if f.Until != nil {
		where += fmt.Sprintf(" AND ts <= $%d", len(args)+1)
		args = append(args, *f.Until)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	total, err := collectOne[int64](q.query(ctx, "SELECT count(*) FROM audit_logs "+where, args...))
	if err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	logs, err := collect[AuditLog](q.query(ctx,
		`SELECT id,ts,admin_id,admin_username,action,target_type,target_id,before_state,after_state,
			detail,ip::text AS ip,request_id FROM audit_logs `+where+
			fmt.Sprintf(" ORDER BY ts DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...))
	if err != nil {
		return nil, 0, err
	}
	return logs, int(*total), nil
}

// ===== 风险事件 =====

func (q *Queries) InsertRiskEvent(ctx context.Context, kind, severity, subject, action string, detail map[string]any) error {
	b, _ := json.Marshal(detail)
	_, err := q.exec(ctx, `
		INSERT INTO risk_events(kind,severity,subject,action,detail) VALUES($1,$2,$3,$4,$5)`,
		kind, severity, subject, action, b)
	return err
}

type RiskFilter struct {
	Kind  string
	Since *time.Time
	Limit int
}

func (q *Queries) ListRiskEvents(ctx context.Context, f RiskFilter) ([]*RiskEvent, error) {
	where := "WHERE 1=1"
	args := []any{}
	if f.Kind != "" {
		where += fmt.Sprintf(" AND kind=$%d", len(args)+1)
		args = append(args, f.Kind)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	args = append(args, f.Limit)
	return collect[RiskEvent](q.query(ctx,
		`SELECT id,ts,kind,severity,subject,detail,action FROM risk_events `+where+
			fmt.Sprintf(" ORDER BY ts DESC LIMIT $%d", len(args)), args...))
}

// ===== 封禁 =====

func (q *Queries) CreateBan(ctx context.Context, kind, value, reason, by string, until *time.Time) (*Ban, error) {
	var byP *string
	if by != "" {
		byP = &by
	}
	row, rerr := q.query(ctx, `
		INSERT INTO bans(kind,value,reason,created_by,until) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT (kind,value) DO UPDATE SET reason=EXCLUDED.reason, until=EXCLUDED.until
		RETURNING id,kind,value,reason,until,created_by,created_at`,
		kind, value, reason, byP, until)
	return collectOne[Ban](row, rerr)
}

func (q *Queries) DeleteBan(ctx context.Context, kind, value string) error {
	_, err := q.exec(ctx, `DELETE FROM bans WHERE kind=$1 AND value=$2`, kind, value)
	return err
}

func (q *Queries) ListBans(ctx context.Context) ([]*Ban, error) {
	return collect[Ban](q.query(ctx,
		`SELECT id,kind,value,reason,until,created_by,created_at FROM bans ORDER BY created_at DESC`))
}

// IsBanned 检查封禁（kind+value；until NULL=永久，until>now 生效）。
func (q *Queries) IsBanned(ctx context.Context, kind, value string) (bool, error) {
	var n int64
	err := q.queryRow(ctx, `
		SELECT count(*) FROM bans
		WHERE kind=$1 AND value=$2 AND (until IS NULL OR until > now())`, kind, value).Scan(&n)
	return n > 0, err
}

// ===== 统计聚合 =====

func (q *Queries) CountCardsByStatus(ctx context.Context) (map[string]int64, error) {
	rows, err := q.query(ctx, `SELECT status, count(*) FROM cards GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var s string
		var n int64
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

func (q *Queries) CountLicensesByStatusSingle(ctx context.Context, status string) (int64, error) {
	var n int64
	err := q.queryRow(ctx, `SELECT count(*) FROM licenses WHERE status=$1`, status).Scan(&n)
	return n, err
}

func (q *Queries) CountRecentHeartbeats(ctx context.Context, within time.Duration) (int64, error) {
	var n int64
	err := q.queryRow(ctx,
		`SELECT count(*) FROM devices WHERE status='active' AND last_heartbeat_at > now() - make_interval(secs=>$1)`,
		int(within.Seconds())).Scan(&n)
	return n, err
}

// CountMisc 一次取多个计数：产品、套餐、代理商、7 日激活、24h 风险事件。
func (q *Queries) CountMisc(ctx context.Context) (products, plans, agents, act7d, risk24h int64, err error) {
	err = q.queryRow(ctx, `SELECT
		(SELECT count(*) FROM products),
		(SELECT count(*) FROM plans),
		(SELECT count(*) FROM agents),
		(SELECT count(*) FROM activations WHERE created_at > now() - interval '7 days'),
		(SELECT count(*) FROM risk_events WHERE ts > now() - interval '24 hours')`).
		Scan(&products, &plans, &agents, &act7d, &risk24h)
	return
}

// ListBatches 批次列表（agent 范围可选），同时返回符合条件的总数。
func (q *Queries) ListBatches(ctx context.Context, agentID string, limit, offset int) ([]*CardBatch, int, error) {
	where := "WHERE 1=1"
	args := []any{}
	if agentID != "" {
		where = "WHERE agent_id=$1"
		args = append(args, agentID)
	}
	var total int64
	if err := q.queryRow(ctx, `SELECT count(*) FROM card_batches `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	args = append(args, limit, offset)
	batches, err := collect[CardBatch](q.query(ctx,
		`SELECT id,agent_id,product_id,plan_id,quantity,prefix,note,created_by,created_at
		 FROM card_batches `+where+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...))
	if err != nil {
		return nil, 0, err
	}
	return batches, int(total), nil
}

// ===== KEX 公钥登记 =====

func (q *Queries) UpsertKexKey(ctx context.Context, kid, pub, alg string, active bool) error {
	_, err := q.exec(ctx, `
		INSERT INTO kex_keys(kid,pub,alg,active) VALUES($1,$2,$3,$4)
		ON CONFLICT (kid) DO UPDATE SET pub=EXCLUDED.pub, active=EXCLUDED.active`,
		kid, pub, alg, active)
	return err
}

func (q *Queries) ActiveKexKeys(ctx context.Context) ([]map[string]any, error) {
	rows, err := q.query(ctx, `SELECT kid,pub,alg,active,created_at FROM kex_keys ORDER BY active DESC, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var kid, pub, alg string
		var active bool
		var ts time.Time
		if err := rows.Scan(&kid, &pub, &alg, &active, &ts); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"kid": kid, "pub": pub, "alg": alg, "active": active, "created_at": ts})
	}
	return out, rows.Err()
}
