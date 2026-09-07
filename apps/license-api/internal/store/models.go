package store

import (
	"time"
)

// 所有与列名不完全同名的字段都带 db 标签（pgx RowToStructByName 依赖）。

type Agent struct {
	ID           string    `json:"id" db:"id"`
	Name         string    `json:"name" db:"name"`
	ParentID     *string   `json:"parent_id" db:"parent_id"`
	BalanceCents int64     `json:"balance_cents" db:"balance_cents"`
	Status       string    `json:"status" db:"status"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type AgentTransaction struct {
	ID           int64     `json:"id" db:"id"`
	AgentID      string    `json:"agent_id" db:"agent_id"`
	AmountCents  int64     `json:"amount_cents" db:"amount_cents"`
	BalanceAfter int64     `json:"balance_after" db:"balance_after"`
	Kind         string    `json:"kind" db:"kind"`
	RefBatchID   *string   `json:"ref_batch_id" db:"ref_batch_id"`
	Note         *string   `json:"note" db:"note"`
	CreatedBy    *string   `json:"created_by" db:"created_by"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type Product struct {
	ID        string    `json:"id" db:"id"`
	Code      string    `json:"code" db:"code"`
	Name      string    `json:"name" db:"name"`
	Status    string    `json:"status" db:"status"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Plan struct {
	ID              string    `json:"id" db:"id"`
	ProductID       string    `json:"product_id" db:"product_id"`
	Code            string    `json:"code" db:"code"`
	Name            string    `json:"name" db:"name"`
	Kind            string    `json:"kind" db:"kind"`
	DurationDays    int       `json:"duration_days" db:"duration_days"`
	FixedExpiryDays int       `json:"fixed_expiry_days" db:"fixed_expiry_days"`
	UsesTotal       int       `json:"uses_total" db:"uses_total"`
	DeviceLimit     int       `json:"device_limit" db:"device_limit"`
	ConcurrentLimit int       `json:"concurrent_limit" db:"concurrent_limit"`
	Features        []string  `json:"features" db:"features"`
	OfflineGrace    int       `json:"offline_grace_seconds" db:"offline_grace_seconds"`
	LeaseTTL        int       `json:"lease_ttl_seconds" db:"lease_ttl_seconds"`
	HeartbeatSec    int       `json:"heartbeat_interval_seconds" db:"heartbeat_interval_seconds"`
	RebindCooldownH int       `json:"rebind_cooldown_hours" db:"rebind_cooldown_hours"`
	MonthlyRebind   int       `json:"monthly_rebind_limit" db:"monthly_rebind_limit"`
	MinClientVer    string    `json:"min_client_version" db:"min_client_version"`
	PriceCents      int64     `json:"price_cents" db:"price_cents"`
	Status          string    `json:"status" db:"status"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

type CardBatch struct {
	ID        string    `json:"id" db:"id"`
	AgentID   *string   `json:"agent_id" db:"agent_id"`
	ProductID string    `json:"product_id" db:"product_id"`
	PlanID    string    `json:"plan_id" db:"plan_id"`
	Quantity  int       `json:"quantity" db:"quantity"`
	Prefix    string    `json:"prefix" db:"prefix"`
	Note      *string   `json:"note" db:"note"`
	CreatedBy string    `json:"created_by" db:"created_by"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Card struct {
	ID               string     `json:"id" db:"id"`
	BatchID          string     `json:"batch_id" db:"batch_id"`
	AgentID          *string    `json:"agent_id" db:"agent_id"`
	AgentName        *string    `json:"agent_name" db:"agent_name"`
	ProductID        string     `json:"product_id" db:"product_id"`
	PlanID           string     `json:"plan_id" db:"plan_id"`
	Lookup           string     `json:"-" db:"lookup"`
	SecretCiphertext []byte     `json:"-" db:"secret_ciphertext"`
	SecretNonce      []byte     `json:"-" db:"secret_nonce"`
	SecretKeyVersion string     `json:"-" db:"secret_key_version"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	Prefix           string     `json:"prefix" db:"prefix"`
	Kind             string     `json:"kind" db:"kind"`
	PlanKind         string     `json:"plan_kind" db:"plan_kind"`
	DurationDays     int        `json:"duration_days" db:"duration_days"`
	FixedExpiryDays  int        `json:"fixed_expiry_days" db:"fixed_expiry_days"`
	PriceCents       int64      `json:"price_cents" db:"price_cents"`
	Status           string     `json:"status" db:"status"`
	UsesTotal        int        `json:"uses_total" db:"uses_total"`
	UsesLeft         int        `json:"uses_left" db:"uses_left"`
	LicenseID        *string    `json:"license_id" db:"license_id"`
	UsedByUser       *string    `json:"used_by_user" db:"used_by_user"`
	ActivatedAt      *time.Time `json:"activated_at" db:"activated_at"`
	ExpiresAt        *time.Time `json:"expires_at" db:"expires_at"`
	CreatedBy        string     `json:"created_by" db:"created_by"`
	Note             *string    `json:"note" db:"note"` // 卡密备注（管理员可编辑）
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}

type License struct {
	ID            string     `json:"id" db:"id"`
	ProductID     string     `json:"product_id" db:"product_id"`
	PlanID        string     `json:"plan_id" db:"plan_id"`
	AgentID       *string    `json:"agent_id" db:"agent_id"`
	OriginCardID  string     `json:"origin_card_id" db:"origin_card_id"`
	Status        string     `json:"status" db:"status"`
	UsesLeft      *int       `json:"uses_left" db:"uses_left"`
	ActivatedAt   time.Time  `json:"activated_at" db:"activated_at"`
	ExpiresAt     *time.Time `json:"expires_at" db:"expires_at"`
	PolicyVersion int64      `json:"policy_version" db:"policy_version"`
	Note          *string    `json:"note" db:"note"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

type Device struct {
	ID              string     `json:"id" db:"id"`
	LicenseID       string     `json:"license_id" db:"license_id"`
	FingerprintHash string     `json:"fingerprint_hash" db:"fingerprint_hash"`
	DevicePub       string     `json:"device_pub" db:"device_pub"`
	PubKty          string     `json:"pub_kty" db:"pub_kty"`
	TrustLevel      string     `json:"trust_level" db:"trust_level"`
	HwSnapshot      []byte     `json:"hw_snapshot" db:"hw_snapshot"`
	Status          string     `json:"status" db:"status"`
	BoundAt         time.Time  `json:"bound_at" db:"bound_at"`
	UnboundAt       *time.Time `json:"unbound_at" db:"unbound_at"`
	UnboundBy       *string    `json:"unbound_by" db:"unbound_by"`
	LastHeartbeat   *time.Time `json:"last_heartbeat_at" db:"last_heartbeat_at"`
	LastIP          *string    `json:"last_ip" db:"last_ip"`
	ClientVersion   *string    `json:"client_version" db:"client_version"`
	LastSeq         int64      `json:"last_seq" db:"last_seq"`
}

type Admin struct {
	ID                 string     `json:"id" db:"id"`
	Username           string     `json:"username" db:"username"`
	PasswordHash       string     `json:"-" db:"password_hash"`
	DisplayName        string     `json:"display_name" db:"display_name"`
	Role               string     `json:"role" db:"role"`
	AgentID            *string    `json:"agent_id" db:"agent_id"`
	TOTPSecret         *string    `json:"-" db:"totp_secret"`
	MFAEnabled         bool       `json:"mfa_enabled" db:"mfa_enabled"`
	Status             string     `json:"status" db:"status"`
	FailedAttempts     int        `json:"failed_attempts" db:"failed_attempts"`
	LockedUntil        *time.Time `json:"locked_until" db:"locked_until"`
	MustChangePassword bool       `json:"must_change_password" db:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	LastLoginAt        *time.Time `json:"last_login_at" db:"last_login_at"`
}

type AdminSession struct {
	ID        string    `db:"id"`
	AdminID   string    `db:"admin_id"`
	TokenHash string    `db:"token_hash"`
	CSRFToken string    `db:"csrf_token"`
	MFAPassed bool      `db:"mfa_passed"`
	ExpiresAt time.Time `db:"expires_at"`
}

type AuditLog struct {
	ID            int64     `json:"id" db:"id"`
	TS            time.Time `json:"ts" db:"ts"`
	AdminID       *string   `json:"admin_id" db:"admin_id"`
	AdminUsername *string   `json:"admin_username" db:"admin_username"`
	Action        string    `json:"action" db:"action"`
	TargetType    *string   `json:"target_type" db:"target_type"`
	TargetID      *string   `json:"target_id" db:"target_id"`
	BeforeState   []byte    `json:"before_state" db:"before_state"`
	AfterState    []byte    `json:"after_state" db:"after_state"`
	Detail        []byte    `json:"detail" db:"detail"`
	IP            *string   `json:"ip" db:"ip"`
	RequestID     *string   `json:"request_id" db:"request_id"`
}

type RiskEvent struct {
	ID       int64     `json:"id" db:"id"`
	TS       time.Time `json:"ts" db:"ts"`
	Kind     string    `json:"kind" db:"kind"`
	Severity string    `json:"severity" db:"severity"`
	Subject  *string   `json:"subject" db:"subject"`
	Detail   []byte    `json:"detail" db:"detail"`
	Action   string    `json:"action" db:"action"`
}

type Ban struct {
	ID        string     `json:"id" db:"id"`
	Kind      string     `json:"kind" db:"kind"`
	Value     string     `json:"value" db:"value"`
	Reason    *string    `json:"reason" db:"reason"`
	Until     *time.Time `json:"until" db:"until"`
	CreatedBy *string    `json:"created_by" db:"created_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}
