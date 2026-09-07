package service

import (
	"context"
	"log/slog"

	"github.com/vertify/license-platform/internal/cache"
	"github.com/vertify/license-platform/internal/store"
)

// Risk 风控：风险事件落库 + 卡密枚举检测 + 渐进式封禁。
type Risk struct {
	Store *store.Store
	Cache *cache.Cache
}

// Record 记录风险事件。失败只打日志（风控不可用不应阻断主流程）。
func (r *Risk) Record(ctx context.Context, kind, severity, subject string, detail any) {
	detailStr := ""
	if s, ok := detail.(string); ok {
		detailStr = s
	}
	detailMap := map[string]any{"detail": detail}
	err := r.Store.Q().InsertRiskEvent(ctx, kind, severity, subject, actionFor(kind, severity), map[string]any{
		"info": detailMap,
		"text": detailStr,
	})
	if err != nil {
		slog.Warn("risk: insert failed", "kind", kind, "err", err)
	}
}

func actionFor(kind, severity string) string {
	switch {
	case kind == "replay" || kind == "sig_fail" || kind == "seq_regression":
		return "blocked"
	case severity == "critical":
		return "banned"
	case severity == "high":
		return "throttled"
	}
	return "logged"
}

// 枚举检测：同一 IP 对卡密接口的高频失败。
const (
	enumWindow    = 10 * 60 // 10 分钟
	enumThreshold = 20      // 阈值后渐进封禁
)

// CardFailure 记录一次卡密失败（枚举检测入口）。
// 返回 true 表示该 IP 已触发枚举封禁。
func (r *Risk) CardFailure(ctx context.Context, ip string) bool {
	key := "enum:" + ip
	n, err := r.Cache.Incr(ctx, key, enumWindow)
	if err != nil {
		return false
	}
	if n == enumThreshold {
		r.Record(ctx, "enum_burst", "high", ip, map[string]any{"count": n})
	}
	return n > enumThreshold
}

// UserSignupBurst 注册接口突发检测（同 IP 高频注册 → 渐进限流）。
func (r *Risk) UserSignupBurst(ctx context.Context, ip string) bool {
	n, err := r.Cache.Incr(ctx, "signup:"+ip, 3600) // 1 小时窗口
	if err != nil {
		return false
	}
	if n == 10 {
		r.Record(ctx, "signup_burst", "medium", ip, map[string]any{"count": n})
	}
	return n > 10
}
