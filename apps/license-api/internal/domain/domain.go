// Package domain 定义许可系统的核心实体、状态机与错误码。
// 状态机以数据库 CHECK 约束固化，服务层不得引入未定义状态。
package domain

import "errors"

// CardStatus 卡密状态机：
//
//	unused ──激活──> active ──冻结──> frozen ──解冻──> active
//	  │                 │                │
//	  │                 ├──兑换续费──> active（延长有效期）
//	  │                 ├──吊销──> revoked（终态）
//	  └──作废──> voided（终态）
//
//	active/frozen 中次数耗尽 → depleted（次卡终态）
type CardStatus string

const (
	CardUnused   CardStatus = "unused"
	CardActive   CardStatus = "active"
	CardFrozen   CardStatus = "frozen"
	CardRevoked  CardStatus = "revoked"
	CardVoided   CardStatus = "voided"
	CardDepleted CardStatus = "depleted"
)

func (s CardStatus) Valid() bool {
	switch s {
	case CardUnused, CardActive, CardFrozen, CardRevoked, CardVoided, CardDepleted:
		return true
	}
	return false
}

// Terminal 卡密是否处于终态。
func (s CardStatus) Terminal() bool {
	return s == CardRevoked || s == CardVoided || s == CardDepleted
}

// LicenseStatus 许可证状态。expired 为派生状态（expires_at < now），不入库。
type LicenseStatus string

const (
	LicenseActive  LicenseStatus = "active"
	LicenseFrozen  LicenseStatus = "frozen"
	LicenseRevoked LicenseStatus = "revoked"
	LicenseVoided  LicenseStatus = "voided"
)

func (s LicenseStatus) Valid() bool {
	switch s {
	case LicenseActive, LicenseFrozen, LicenseRevoked, LicenseVoided:
		return true
	}
	return false
}

// DeviceStatus 设备绑定状态。
type DeviceStatus string

const (
	DeviceActive  DeviceStatus = "active"
	DeviceUnbound DeviceStatus = "unbound"
)

// AdminRole 后台角色。权限在服务端逐请求校验，前端仅做展示控制。
type AdminRole string

const (
	AdminSuperAdmin AdminRole = "superadmin"
	AdminAdmin      AdminRole = "admin"
	AdminAgent      AdminRole = "agent"
	AdminAuditor    AdminRole = "auditor"
	AdminViewer     AdminRole = "viewer"
)

// Permission 权限点。
type Permission string

const (
	PermProductsRead   Permission = "products:read"
	PermProductsWrite  Permission = "products:write"
	PermCardsRead      Permission = "cards:read"
	PermCardsExport    Permission = "cards:export" // 高危：明文卡密导出
	PermCardsManage    Permission = "cards:manage"
	PermLicensesRead   Permission = "licenses:read"
	PermLicensesManage Permission = "licenses:manage"
	PermDevicesManage  Permission = "devices:manage"
	PermAdminsManage   Permission = "admins:manage"
	PermAgentsManage   Permission = "agents:manage"
	PermAuditRead      Permission = "audit:read"
	PermRiskManage     Permission = "risk:manage"
	PermStatsRead      Permission = "stats:read"
	PermUsersManage    Permission = "users:manage"
)

var rolePermissions = map[AdminRole][]Permission{
	AdminSuperAdmin: allPermissions(),
	AdminAdmin: {
		PermProductsRead, PermProductsWrite,
		PermCardsRead, PermCardsExport, PermCardsManage,
		PermLicensesRead, PermLicensesManage, PermDevicesManage,
		PermAuditRead, PermRiskManage, PermStatsRead,
	},
	// 代理商只运营自己的卡密：制卡、查看/导出/管理自己名下的卡与授权。
	// 产品目录列表对全部已登录管理员开放（制卡下拉需要），但管理权不在代理商。
	AdminAgent: {
		PermCardsRead, PermCardsExport, PermCardsManage,
		PermLicensesRead,
	},
	AdminAuditor: {PermAuditRead, PermStatsRead, PermCardsRead, PermLicensesRead},
	AdminViewer:  {PermCardsRead, PermLicensesRead, PermStatsRead, PermProductsRead},
}

func allPermissions() []Permission {
	return []Permission{
		PermProductsRead, PermProductsWrite, PermCardsRead, PermCardsExport,
		PermCardsManage, PermLicensesRead, PermLicensesManage, PermDevicesManage,
		PermAdminsManage, PermAgentsManage, PermAuditRead, PermRiskManage, PermStatsRead,
		PermUsersManage,
	}
}

// RoleHas 判断角色是否拥有权限。
func RoleHas(r AdminRole, p Permission) bool {
	for _, perm := range rolePermissions[r] {
		if perm == p {
			return true
		}
	}
	return false
}

// RolePermissions 返回角色全部权限（后台 /me 接口用）。
func RolePermissions(r AdminRole) []Permission {
	return rolePermissions[r]
}

// PlanPolicy 套餐策略（license_plans 行的策略字段聚合）。
type PlanPolicy struct {
	DurationDays        int      `json:"duration_days"`
	FixedExpiryDays     int      `json:"fixed_expiry_days"`
	DeviceLimit         int      `json:"device_limit"`
	ConcurrentLimit     int      `json:"concurrent_limit"`
	Features            []string `json:"features"`
	OfflineGraceSeconds int      `json:"offline_grace_seconds"`
	LeaseTTLSeconds     int      `json:"lease_ttl_seconds"`
	HeartbeatInterval   int      `json:"heartbeat_interval_seconds"`
	RebindCooldownHours int      `json:"rebind_cooldown_hours"`
	MonthlyRebindLimit  int      `json:"monthly_rebind_limit"`
}

// 领域错误。HTTP 层映射为稳定错误码，绝不向客户端泄漏内部细节。
var (
	ErrCardNotFound        = errors.New("card not found")
	ErrCardInvalidFormat   = errors.New("card format invalid")
	ErrCardNotUsable       = errors.New("card not usable")
	ErrCardFrozen          = errors.New("card frozen")
	ErrCardRevoked         = errors.New("card revoked")
	ErrCardVoided          = errors.New("card voided")
	ErrCardDepleted        = errors.New("card depleted")
	ErrLicenseFrozen       = errors.New("license frozen")
	ErrLicenseRevoked      = errors.New("license revoked")
	ErrLicenseExpired      = errors.New("license expired")
	ErrLicenseVoided       = errors.New("license voided")
	ErrDeviceLimit         = errors.New("device limit reached")
	ErrConcurrentLimit     = errors.New("concurrent session limit reached")
	ErrDeviceNotFound      = errors.New("device not found")
	ErrDeviceUnbound       = errors.New("device unbound")
	ErrRebindCooldown      = errors.New("rebind cooldown active")
	ErrRebindLimit         = errors.New("monthly rebind limit reached")
	ErrBadSignature        = errors.New("signature verification failed")
	ErrReplayDetected      = errors.New("replay detected")
	ErrSeqRegression       = errors.New("sequence regression")
	ErrRateLimited         = errors.New("rate limited")
	ErrBanned              = errors.New("blocked by policy")
	ErrPlanRetired         = errors.New("plan retired")
	ErrPlanInUse           = errors.New("plan is already used")
	ErrPlanNotRetired      = errors.New("plan must be retired before delete")
	ErrProductRetired      = errors.New("product retired")
	ErrVersionTooOld       = errors.New("client version too old")
	ErrInsufficientBalance = errors.New("agent balance insufficient")
	ErrAgentNotFound       = errors.New("agent not found")
	ErrUserExists          = errors.New("user already exists")
	ErrUserDisabled        = errors.New("user disabled")
	ErrMachineBound        = errors.New("machine already bound")
	ErrBadSecurityCode     = errors.New("bad security code")
	ErrAccountExpired      = errors.New("account expired")
	ErrBadUsername         = errors.New("bad username")
)
