// Package httpapi 提供 chi 路由、中间件与稳定的错误映射。
// 客户端 API 与管理面分端口部署；错误信息绝不泄漏内部细节。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/service"
	"github.com/vertify/license-platform/internal/store"
)

// ===== 通用工具 =====

type ctxKey string

const (
	ctxRequestID ctxKey = "request_id"
	ctxClientIP  ctxKey = "client_ip"
	ctxAdmin     ctxKey = "admin_ctx"
)

func RequestID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

func ClientIP(r *http.Request) string {
	if v, ok := r.Context().Value(ctxClientIP).(string); ok {
		return v
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errBody struct {
	Error errPayload `json:"error"`
}

type errPayload struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// ErrorWriter 统一错误出口：仅暴露稳定错误码与泛化文案。
func ErrorWriter(w http.ResponseWriter, r *http.Request, err error, status int, code, message string) {
	writeJSON(w, status, errBody{Error: errPayload{Code: code, Message: message, RequestID: RequestID(r)}})
}

// MapError 领域错误 → HTTP 状态与稳定错误码。
func MapError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNoRows):
		ErrorWriter(w, r, err, 404, "NOT_FOUND", "对象不存在")
	case errors.Is(err, domain.ErrPlanInUse):
		ErrorWriter(w, r, err, 409, "PLAN_IN_USE", "该套餐存在已激活或历史卡密记录，无法删除（数据完整性保护）")
	case errors.Is(err, domain.ErrPlanNotRetired):
		ErrorWriter(w, r, err, 409, "PLAN_NOT_RETIRED", "请先将套餐退役，再删除")
	case errors.Is(err, domain.ErrCardNotFound):
		ErrorWriter(w, r, err, 404, "CARD_NOT_FOUND", "卡密不存在")
	case errors.Is(err, domain.ErrCardInvalidFormat):
		ErrorWriter(w, r, err, 400, "CARD_INVALID", "卡密格式错误")
	case errors.Is(err, domain.ErrCardNotUsable),
		errors.Is(err, domain.ErrPlanRetired),
		errors.Is(err, domain.ErrProductRetired):
		ErrorWriter(w, r, err, 409, "CARD_NOT_USABLE", "卡密不可用")
	case errors.Is(err, domain.ErrCardFrozen):
		ErrorWriter(w, r, err, 403, "CARD_FROZEN", "卡密已冻结")
	case errors.Is(err, domain.ErrCardRevoked):
		ErrorWriter(w, r, err, 403, "CARD_REVOKED", "卡密已吊销")
	case errors.Is(err, domain.ErrCardVoided):
		ErrorWriter(w, r, err, 403, "CARD_VOIDED", "卡密已作废")
	case errors.Is(err, domain.ErrCardDepleted):
		ErrorWriter(w, r, err, 403, "CARD_DEPLETED", "卡密已用尽")
	case errors.Is(err, domain.ErrLicenseFrozen):
		ErrorWriter(w, r, err, 403, "LICENSE_FROZEN", "许可证已冻结")
	case errors.Is(err, domain.ErrLicenseRevoked):
		ErrorWriter(w, r, err, 403, "LICENSE_REVOKED", "许可证已吊销")
	case errors.Is(err, domain.ErrLicenseVoided):
		ErrorWriter(w, r, err, 403, "LICENSE_VOIDED", "许可证已作废")
	case errors.Is(err, domain.ErrLicenseExpired):
		ErrorWriter(w, r, err, 403, "LICENSE_EXPIRED", "许可证已过期")
	case errors.Is(err, domain.ErrDeviceLimit):
		ErrorWriter(w, r, err, 409, "DEVICE_LIMIT", "设备数量已达上限，请先解绑设备")
	case errors.Is(err, domain.ErrConcurrentLimit):
		ErrorWriter(w, r, err, 409, "CONCURRENT_LIMIT", "并发会话已达上限")
	case errors.Is(err, domain.ErrDeviceNotFound):
		ErrorWriter(w, r, err, 404, "DEVICE_NOT_FOUND", "设备不存在")
	case errors.Is(err, domain.ErrDeviceUnbound):
		ErrorWriter(w, r, err, 409, "DEVICE_UNBOUND", "设备已解绑")
	case errors.Is(err, domain.ErrBadSignature):
		ErrorWriter(w, r, err, 401, "BAD_SIGNATURE", "签名验证失败")
	case errors.Is(err, domain.ErrReplayDetected):
		ErrorWriter(w, r, err, 409, "REPLAY_DETECTED", "检测到重放请求")
	case errors.Is(err, domain.ErrSeqRegression):
		ErrorWriter(w, r, err, 409, "SEQ_REGRESSION", "序列号异常")
	case errors.Is(err, domain.ErrRateLimited):
		ErrorWriter(w, r, err, 429, "RATE_LIMITED", "请求过于频繁")
	case errors.Is(err, domain.ErrBanned):
		ErrorWriter(w, r, err, 403, "BANNED", "已被策略拦截")
	case errors.Is(err, domain.ErrAgentNotFound):
		ErrorWriter(w, r, err, 404, "AGENT_NOT_FOUND", "代理商不存在")
	case errors.Is(err, domain.ErrInsufficientBalance):
		ErrorWriter(w, r, err, 409, "BALANCE_INSUFFICIENT", "代理余额不足，请联系总经销充值")

	case errors.Is(err, service.ErrBadCredentials):
		ErrorWriter(w, r, err, 401, "BAD_CREDENTIALS", "用户名或密码错误")
	case errors.Is(err, domain.ErrUserExists):
		ErrorWriter(w, r, err, 409, "USER_EXISTS", "用户名已存在")
	case errors.Is(err, domain.ErrUserDisabled):
		ErrorWriter(w, r, err, 403, "USER_DISABLED", "账号已被禁用")
	case errors.Is(err, domain.ErrMachineBound):
		ErrorWriter(w, r, err, 409, "MACHINE_BOUND", "该账号已绑定其他机器")
	case errors.Is(err, domain.ErrBadSecurityCode):
		ErrorWriter(w, r, err, 400, "BAD_SECURITY_CODE", "安全码错误")
	case errors.Is(err, domain.ErrAccountExpired):
		ErrorWriter(w, r, err, 403, "ACCOUNT_EXPIRED", "账号已到期")
	case errors.Is(err, domain.ErrBadUsername):
		ErrorWriter(w, r, err, 400, "BAD_USERNAME", "用户名格式错误（3-32位字母数字下划线）")
	case errors.Is(err, domain.ErrVersionTooOld):
		ErrorWriter(w, r, err, 426, "VERSION_TOO_OLD", "客户端版本过低，请升级")
	default:
		// 信封解密/协议错误等归为 400，其余 500 且不泄漏细节
		if errors.Is(err, errEnvelope) {
			ErrorWriter(w, r, err, 400, "ENVELOPE_INVALID", "载荷解密失败")
			return
		}
		// 数据库约束类错误 → 语义化状态码（避免无意义的 500）
		if store.IsUnique(err) {
			ErrorWriter(w, r, err, 409, "ALREADY_EXISTS", "资源已存在")
			return
		}
		if store.IsForeignKey(err) {
			ErrorWriter(w, r, err, 400, "BAD_REFERENCE", "引用的对象不存在")
			return
		}
		if store.IsInvalidInput(err) {
			ErrorWriter(w, r, err, 404, "NOT_FOUND", "对象不存在")
			return
		}
		slog.Error("internal error", "err", err, "request_id", RequestID(r), "path", r.URL.Path)
		ErrorWriter(w, r, err, 500, "INTERNAL", "内部错误")
	}
}

// errEnvelope 标记信封/协议解析错误（避免把 crypto 内部错误细节暴露给客户端）。
var errEnvelope = errors.New("envelope/protocol")

// ===== 中间件 =====

// RequestID 注入请求 ID（含上游透传）。
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" || len(rid) > 64 {
			rid = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", rid)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, rid)))
	})
}

// RealIP 严格的来源 IP 提取：仅当直连地址属于可信代理网段时才采信 X-Forwarded-For。
func RealIP(trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.RemoteAddr
			if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				host = h
			}
			ip := net.ParseIP(host)
			client := host
			if ip != nil && trustedCIDRs != nil && containsIP(trustedCIDRs, ip) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					parts := strings.Split(xff, ",")
					// 最左侧为最初客户端；逐跳可信时才成立
					client = strings.TrimSpace(parts[0])
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxClientIP, client)))
		})
	}
}

func containsIP(cidrs []*net.IPNet, ip net.IP) bool {
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// SecurityHeaders 安全响应头（管理面与 API 通用）。
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Recover 恐慌恢复，避免泄漏堆栈给客户端。
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic", "rec", rec, "path", r.URL.Path, "request_id", RequestID(r))
				ErrorWriter(w, r, errors.New("panic"), 500, "INTERNAL", "内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// LogAccess 结构化访问日志（不含 body，杜绝敏感信息进日志）。
func LogAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		slog.Info("access",
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"dur_ms", time.Since(start).Milliseconds(),
			"ip", ClientIP(r), "request_id", RequestID(r))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// RateLimit IP 维度限流。
func RateLimit(svc *service.Services, limit int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, _, err := svc.Cache.RateLimit(r.Context(), "ip:"+ClientIP(r), limit, time.Minute)
			if err != nil {
				// 限流组件故障时放行（可用性优先），但记录
				slog.Warn("ratelimit error", "err", err)
				next.ServeHTTP(w, r)
				return
			}
			if !ok {
				ErrorWriter(w, r, domain.ErrRateLimited, 429, "RATE_LIMITED", "请求过于频繁")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BodyLimit 限制请求体大小（用作中间件）。
func BodyLimit(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// limitBody 单端点体积限制（包装单个 handler 用）。
func limitBody(n int64, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		h(w, r)
	}
}

func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

// ===== 后台可配置的接口级限流（30s 内存缓存） =====

type ScopeRateLimiter struct {
	svc      *service.Services
	mu       sync.Mutex
	conf     map[string]int
	loadedAt time.Time
}

func NewScopeRateLimiter(svc *service.Services) *ScopeRateLimiter {
	return &ScopeRateLimiter{svc: svc, conf: map[string]int{}}
}

func (l *ScopeRateLimiter) limit(scope string, fallback int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.loadedAt) > 30*time.Second {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if m, err := l.svc.Store.Q().AllApiRateLimits(ctx); err == nil {
			l.conf = m
			l.loadedAt = time.Now()
		}
		cancel()
	}
	if v, ok := l.conf[scope]; ok && v > 0 {
		return v
	}
	return fallback
}

func (l *ScopeRateLimiter) Invalidate() {
	l.mu.Lock()
	l.loadedAt = time.Time{}
	l.mu.Unlock()
}

// Middleware(scope, fallback)：后台配置优先，否则用 fallback。
func (l *ScopeRateLimiter) Middleware(scope string, fallback int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := l.limit(scope, fallback)
			ok, _, err := l.svc.Cache.RateLimit(r.Context(), "scope:"+scope+":"+ClientIP(r), limit, time.Minute)
			if err != nil {
				slog.Warn("ratelimit error", "err", err)
				next.ServeHTTP(w, r)
				return
			}
			if !ok {
				ErrorWriter(w, r, domain.ErrRateLimited, 429, "RATE_LIMITED", "请求过于频繁")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
