package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/service"
	"github.com/vertify/license-platform/internal/store"
)

// newJSONDecoder 严格 JSON 解码（拒绝未知字段，收窄协议面）。
func newJSONDecoder(rd io.Reader) *json.Decoder {
	dec := json.NewDecoder(rd)
	dec.DisallowUnknownFields()
	return dec
}

const sessionCookie = "vft_admin_session"

// AdminRouter 管理面 API（/admin/v1）。独立端口部署 + 严格会话/CSRF/RBAC。
func AdminRouter(svc *service.Services, trustedProxies []*net.IPNet) http.Handler {
	r := chi.NewRouter()
	r.Use(RealIP(trustedProxies), Recover, RequestIDMiddleware, LogAccess, SecurityHeaders)

	r.Route("/admin/v1", func(r chi.Router) {
		// 认证
		r.Post("/auth/login", limitBody(8<<10, handleAdminLogin(svc)))
		r.Post("/auth/logout", handleAdminLogout(svc))

		// 需要会话
		r.Group(func(r chi.Router) {
			r.Use(requireAdminSession(svc))
			r.Get("/auth/me", handleMe(svc))
			r.Post("/auth/mfa/setup", handleMFASetup(svc))
			r.Post("/auth/mfa/enable", handleMFAEnable(svc))
			r.Post("/auth/mfa/disable", handleMFADisable(svc))
			r.Post("/auth/password", handlePasswordChange(svc))

			// 产品/套餐目录对全部已登录管理员只读开放：代理商制卡下拉需要；
			// 目录本身不含敏感数据，管理（写）仍需 products:write。
			r.Get("/products", handleListProducts(svc))
			r.Post("/products", requirePerm(svc, domain.PermProductsWrite)(handleCreateProduct(svc)))
			r.Post("/products/{id}/status", requirePerm(svc, domain.PermProductsWrite)(handleProductStatus(svc)))
			r.Get("/plans", handleListPlans(svc))
			r.Post("/plans", requirePerm(svc, domain.PermProductsWrite)(handleCreatePlan(svc)))
			r.Get("/plans/{id}", handlePlanDetail(svc))
			r.Put("/plans/{id}", requirePerm(svc, domain.PermProductsWrite)(handleUpdatePlan(svc)))
			r.Delete("/plans/{id}", requirePerm(svc, domain.PermProductsWrite)(handleDeletePlan(svc)))
			r.Post("/plans/{id}/status", requirePerm(svc, domain.PermProductsWrite)(handlePlanStatus(svc)))

			r.Get("/batches", requirePerm(svc, domain.PermCardsRead)(handleListBatches(svc)))
			r.Post("/batches", requirePerm(svc, domain.PermCardsManage)(handleCreateBatch(svc)))
			r.Post("/batches/import", requirePerm(svc, domain.PermCardsManage)(handleImportCards(svc)))

			r.Get("/cards", requirePerm(svc, domain.PermCardsRead)(handleListCards(svc)))
			r.Post("/cards/{id}/action", requirePerm(svc, domain.PermCardsManage)(handleCardAction(svc)))
			r.Post("/cards/{id}/note", requirePerm(svc, domain.PermCardsManage)(handleSetCardNote(svc)))
			r.Post("/cards/{id}/reveal", requirePerm(svc, domain.PermCardsExport)(handleRevealCard(svc)))

			r.Get("/licenses", requirePerm(svc, domain.PermLicensesRead)(handleListLicenses(svc)))
			r.Get("/licenses/{id}", requirePerm(svc, domain.PermLicensesRead)(handleLicenseDetail(svc)))
			r.Post("/licenses/{id}/action", requirePerm(svc, domain.PermLicensesManage)(handleLicenseAction(svc)))
			r.Post("/licenses/{id}/note", requirePerm(svc, domain.PermLicensesManage)(handleLicenseNote(svc)))
			r.Post("/licenses/{id}/extend", requirePerm(svc, domain.PermLicensesManage)(handleExtendLicense(svc)))

			r.Get("/devices", requirePerm(svc, domain.PermLicensesRead)(handleListDevices(svc)))
			r.Post("/devices/{id}/unbind", requirePerm(svc, domain.PermDevicesManage)(handleUnbindDevice(svc)))

			r.Get("/agents", requirePerm(svc, domain.PermAgentsManage)(handleListAgents(svc)))
			r.Post("/agents", requirePerm(svc, domain.PermAgentsManage)(handleCreateAgent(svc)))
			r.Get("/agents/{id}/products", requirePerm(svc, domain.PermAgentsManage)(handleAgentProducts(svc)))
			r.Post("/agents/{id}/products", requirePerm(svc, domain.PermAgentsManage)(handleAgentProducts(svc)))
			r.Get("/agents/{id}/account", requirePerm(svc, domain.PermAgentsManage)(handleAgentAccount(svc)))
			r.Post("/agents/{id}/account", requirePerm(svc, domain.PermAgentsManage)(handleAgentAccount(svc)))
			r.Post("/agents/{id}/status", requirePerm(svc, domain.PermAgentsManage)(handleAgentStatus(svc)))
			r.Post("/agents/{id}/balance", requirePerm(svc, domain.PermAgentsManage)(handleAgentBalance(svc)))
			r.Get("/agents/{id}/transactions", requirePerm(svc, domain.PermAgentsManage)(handleAgentTransactions(svc)))

			r.Get("/admins", requirePerm(svc, domain.PermAdminsManage)(handleListAdmins(svc)))
			r.Post("/admins", requirePerm(svc, domain.PermAdminsManage)(handleCreateAdmin(svc)))
			r.Post("/admins/{id}/status", requirePerm(svc, domain.PermAdminsManage)(handleAdminStatus(svc)))

			r.Get("/audit", requirePerm(svc, domain.PermAuditRead)(handleListAudit(svc)))
			r.Get("/risk", requirePerm(svc, domain.PermRiskManage)(handleListRisk(svc)))

			// 终端用户管理（账号制）
			r.Get("/users", requirePerm(svc, domain.PermUsersManage)(handleListUsers(svc)))
			r.Get("/users/{id}", requirePerm(svc, domain.PermUsersManage)(handleUserDetail(svc)))
			r.Post("/users/{id}/action", requirePerm(svc, domain.PermUsersManage)(handleUserAction(svc)))

			// 批量卡密操作
			r.Post("/cards/bulk-action", requirePerm(svc, domain.PermCardsManage)(handleBulkCardAction(svc)))

			// 软件公告 / 版本管理
			r.Get("/messages", requirePerm(svc, domain.PermProductsRead)(handleListMessages(svc)))
			r.Post("/messages", requirePerm(svc, domain.PermProductsWrite)(handleCreateMessage(svc)))
			r.Post("/messages/{id}/enabled", requirePerm(svc, domain.PermProductsWrite)(handleSetMessageEnabled(svc)))
			r.Delete("/messages/{id}", requirePerm(svc, domain.PermProductsWrite)(handleDeleteMessage(svc)))
			r.Get("/versions", requirePerm(svc, domain.PermProductsRead)(handleListVersions(svc)))
			r.Post("/versions", requirePerm(svc, domain.PermProductsWrite)(handleCreateVersion(svc)))
			r.Delete("/versions/{id}", requirePerm(svc, domain.PermProductsWrite)(handleDeleteVersion(svc)))

			// 接口限流配置
			r.Get("/ratelimits", requirePerm(svc, domain.PermRiskManage)(handleListRateLimits(svc)))
			r.Post("/ratelimits", requirePerm(svc, domain.PermRiskManage)(handleSetRateLimit(svc)))
			r.Get("/bans", requirePerm(svc, domain.PermRiskManage)(handleListBans(svc)))
			r.Post("/bans", requirePerm(svc, domain.PermRiskManage)(handleCreateBan(svc)))
			r.Post("/bans/delete", requirePerm(svc, domain.PermRiskManage)(handleDeleteBan(svc)))

			r.Get("/keys", requirePerm(svc, domain.PermStatsRead)(handleKeys(svc)))
			r.Get("/stats", requirePerm(svc, domain.PermStatsRead)(handleStats(svc)))
		})
	})
	return r
}

// ===== 会话中间件 =====

func requireAdminSession(svc *service.Services) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(sessionCookie)
			if err != nil || c.Value == "" {
				ErrorWriter(w, r, nil, 401, "UNAUTHORIZED", "未登录")
				return
			}
			ac, err := svc.ResolveSession(r.Context(), c.Value)
			if err != nil {
				ErrorWriter(w, r, nil, 401, "UNAUTHORIZED", "会话已过期")
				return
			}
			// 写请求校验 CSRF（读请求豁免）
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				if err := svc.CheckCSRF(ac, r.Header.Get("X-CSRF-Token")); err != nil {
					ErrorWriter(w, r, nil, 403, "CSRF", "CSRF 校验失败")
					return
				}
			}
			// 初始管理员或新建管理员必须先改密；安全边界由后端执行，不能仅依赖前端页面。
			if ac.Admin.MustChangePassword {
				path := r.URL.Path
				allowed := path == "/admin/v1/auth/me" || path == "/admin/v1/auth/password" || path == "/admin/v1/auth/logout" ||
					path == "/admin/v1/auth/mfa/setup" || path == "/admin/v1/auth/mfa/enable" || path == "/admin/v1/auth/mfa/disable"
				if !allowed {
					ErrorWriter(w, r, nil, 403, "PASSWORD_CHANGE_REQUIRED", "请先修改初始密码")
					return
				}
			}
			ctx := context.WithValue(r.Context(), ctxAdmin, ac)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func adminCtx(r *http.Request) *service.AdminContext {
	if v, ok := r.Context().Value(ctxAdmin).(*service.AdminContext); ok {
		return v
	}
	return nil
}

func requirePerm(svc *service.Services, perm domain.Permission) func(http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ac := adminCtx(r)
			if ac == nil {
				ErrorWriter(w, r, nil, 401, "UNAUTHORIZED", "未登录")
				return
			}
			if !domain.RoleHas(domain.AdminRole(ac.Admin.Role), perm) {
				ErrorWriter(w, r, nil, 403, "FORBIDDEN", "无权限")
				return
			}
			next.ServeHTTP(w, r)
		}
	}
}

// agentScope 数据范围：agent 角色强制限定自己的 agent_id。
func agentScope(r *http.Request) string {
	if ac := adminCtx(r); ac != nil && ac.Admin.Role == string(domain.AdminAgent) && ac.Admin.AgentID != nil {
		return *ac.Admin.AgentID
	}
	return ""
}

// ===== 认证 =====

func handleAdminLogin(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// IP 级限流：防跨账户密码喷洒（账户锁定只防单账户爆破）
		limit := svc.Cfg.AdminLoginRPM
		if limit <= 0 {
			limit = 10
		}
		if ok, _, err := svc.Cache.RateLimit(r.Context(), "adminlogin:"+ClientIP(r), limit, time.Minute); err == nil && !ok {
			ErrorWriter(w, r, nil, 429, "RATE_LIMITED", "请求过于频繁")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TOTP     string `json:"totp"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		res, err := svc.AdminLogin(r.Context(), req.Username, req.Password, req.TOTP,
			ClientIP(r), r.UserAgent(), RequestID(r))
		if err != nil {
			switch err {
			case service.ErrMFARequired:
				writeJSON(w, 200, map[string]any{"mfa_required": true})
				return
			case service.ErrAccountLocked:
				ErrorWriter(w, r, nil, 423, "LOCKED", "账户已锁定，请稍后再试")
			case service.ErrMFABad:
				ErrorWriter(w, r, nil, 401, "MFA_INVALID", "动态码错误")
			case service.ErrSessionGone:
				ErrorWriter(w, r, nil, 500, "INTERNAL", "内部错误")
			default:
				if errors.Is(err, service.ErrBadCredentials) {
					// 统一 401，不区分用户名/密码错误（防枚举）
					ErrorWriter(w, r, nil, 401, "BAD_CREDENTIALS", "用户名或密码错误")
				} else {
					MapError(w, r, err)
				}
			}
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    res.SessionToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   svc.Cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(svc.Cfg.AdminSessionTTL.Seconds()),
		})
		writeJSON(w, 200, map[string]any{
			"mfa_required": false,
			"csrf_token":   res.CSRFToken,
			"admin":        res.Admin,
			"permissions":  domain.RolePermissions(domain.AdminRole(res.Admin.Role)),
		})
	}
}

func handleAdminLogout(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			if ac, err := svc.ResolveSession(r.Context(), c.Value); err == nil {
				_ = svc.Store.Q().RevokeSession(r.Context(), ac.Session.ID)
				svc.Audit(r.Context(), ac, "auth.logout", "", "", nil, nil, nil, ClientIP(r), RequestID(r))
			}
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: svc.Cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleMe(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac := adminCtx(r)
		resp := map[string]any{
			"admin":       ac.Admin,
			"permissions": domain.RolePermissions(domain.AdminRole(ac.Admin.Role)),
			// 当前会话的 CSRF token：前端在 CSRF 失败时据此自愈（改密/换会后旧令牌作废）
			"csrf_token": ac.Session.CSRFToken,
		}
		// agent 角色附带自己名下余额（侧栏展示）
		if ac.Admin.Role == string(domain.AdminAgent) && ac.Admin.AgentID != nil {
			if ag, err := svc.Store.Q().GetAgent(r.Context(), *ac.Admin.AgentID); err == nil {
				resp["balance_cents"] = ag.BalanceCents
			}
		}
		writeJSON(w, 200, resp)
	}
}

func handleMFASetup(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac := adminCtx(r)
		secret, err := svc.MFASetup(r.Context(), ac)
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"secret": secret,
			"uri":    svc.MFAUri(secret, ac.Admin.Username),
		})
	}
}

func handleMFAEnable(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac := adminCtx(r)
		var req struct {
			Code string `json:"code"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.MFAEnable(r.Context(), ac, req.Code); err != nil {
			ErrorWriter(w, r, nil, 400, "MFA_INVALID", "动态码错误")
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleMFADisable(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac := adminCtx(r)
		var req struct {
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.MFADisable(r.Context(), ac, req.Password); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "密码错误")
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handlePasswordChange(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac := adminCtx(r)
		var req struct {
			Old string `json:"old_password"`
			New string `json:"new_password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		// 改密后签发新会话（其余旧会话全部吊销），当前浏览器不强制重登
		token, csrf, err := svc.AdminChangePassword(r.Context(), ac, req.Old, req.New)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "修改失败（旧密码错误或新口令强度不足，需≥12字符）")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   svc.Cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(svc.Cfg.AdminSessionTTL.Seconds()),
		})
		writeJSON(w, 200, map[string]any{"ok": true, "csrf_token": csrf})
	}
}

// ===== 产品 / 套餐 =====

func handleListProducts(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ps, err := svc.Store.Q().ListProducts(r.Context())
		if err != nil {
			MapError(w, r, err)
			return
		}
		// 代理商只看到被开通的产品
		if ac := adminCtx(r); ac.Admin.Role == string(domain.AdminAgent) && ac.Admin.AgentID != nil {
			granted, err := svc.Store.Q().ListAgentProducts(r.Context(), *ac.Admin.AgentID)
			if err != nil {
				MapError(w, r, err)
				return
			}
			set := make(map[string]bool, len(granted))
			for _, id := range granted {
				set[id] = true
			}
			filtered := ps[:0]
			for _, p := range ps {
				if set[p.ID] {
					filtered = append(filtered, p)
				}
			}
			ps = filtered
		}
		writeJSON(w, 200, map[string]any{"items": ps})
	}
}

func handleCreateProduct(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
			Name string `json:"name"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		p, err := svc.CreateProduct(r.Context(), adminCtx(r), req.Code, req.Name, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 201, p)
	}
}

func handleProductStatus(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Status string `json:"status"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.ProductStatus(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Status, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleListPlans(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ps, err := svc.Store.Q().ListPlans(r.Context(), r.URL.Query().Get("product_id"))
		if err != nil {
			MapError(w, r, err)
			return
		}
		// 代理商只看到在售套餐；退役/停售套餐对代理商不可见
		if ac := adminCtx(r); ac.Admin.Role == string(domain.AdminAgent) {
			filtered := ps[:0]
			var granted map[string]bool
			if ac.Admin.AgentID != nil {
				ids, err := svc.Store.Q().ListAgentProducts(r.Context(), *ac.Admin.AgentID)
				if err != nil {
					MapError(w, r, err)
					return
				}
				granted = make(map[string]bool, len(ids))
				for _, id := range ids {
					granted[id] = true
				}
			}
			for _, p := range ps {
				if p.Status == "active" && (granted == nil || granted[p.ProductID]) {
					filtered = append(filtered, p)
				}
			}
			ps = filtered
		}
		writeJSON(w, 200, map[string]any{"items": ps})
	}
}

func handleCreatePlan(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req store.Plan
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		p, err := svc.CreatePlan(r.Context(), adminCtx(r), &req, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 201, p)
	}
}

func handlePlanDetail(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.Store.Q().GetPlan(r.Context(), chiURLParam(r, "id"))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, p)
	}
}

func handleUpdatePlan(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req store.Plan
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		p, err := svc.UpdatePlan(r.Context(), adminCtx(r), chiURLParam(r, "id"), &req, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, p)
	}
}

func handleDeletePlan(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeletePlan(r.Context(), adminCtx(r), chiURLParam(r, "id"), ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}
func handlePlanStatus(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Status string `json:"status"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.PlanStatus(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Status, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// ===== 批次 / 卡密 =====

func handleImportCards(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req service.ImportCardRequest
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		n, err := svc.ImportCards(r.Context(), adminCtx(r), &req, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 201, map[string]any{"imported": n})
	}
}
func handleCreateBatch(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req service.CreateBatchRequest
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		ac := adminCtx(r)
		if ac.Admin.Role == string(domain.AdminAgent) {
			if ac.Admin.AgentID == nil {
				ErrorWriter(w, r, nil, 403, "FORBIDDEN", "无权限")
				return
			}
			req.AgentID = *ac.Admin.AgentID
		}
		res, err := svc.CreateCardBatch(r.Context(), ac, &req, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 201, res)
	}
}

func handleListBatches(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset := pageParams(r)
		batches, total, err := svc.Store.Q().ListBatches(r.Context(), agentScope(r), limit, offset)
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": batches, "total": total})
	}
}

func handleListCards(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset := pageParams(r)
		f := store.CardFilter{
			AgentID:   agentScope(r),
			Prefix:    r.URL.Query().Get("prefix"),
			BatchID:   r.URL.Query().Get("batch_id"),
			Status:    r.URL.Query().Get("status"),
			Kind:      r.URL.Query().Get("kind"),
			PlanID:    r.URL.Query().Get("plan_id"),
			ProductID: r.URL.Query().Get("product_id"),
			Search:    r.URL.Query().Get("q"),
			Limit:     limit, Offset: offset,
		}
		// 总经销/管理员可按代理商筛选（agent 角色已被 agentScope 锁定自己的范围）
		if ac := adminCtx(r); ac != nil && ac.Admin.Role != string(domain.AdminAgent) {
			f.AgentID = r.URL.Query().Get("agent_id")
		}
		cards, total, err := svc.Store.Q().ListCards(r.Context(), f)
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": cards, "total": total})
	}
}

func handleCardAction(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action string `json:"action"`
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.CardAction(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Action, req.Reason, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// ===== 许可证 / 设备 =====

func handleListLicenses(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset := pageParams(r)
		f := store.LicenseFilter{
			AgentID: agentScope(r),
			Status:  r.URL.Query().Get("status"),
			Product: r.URL.Query().Get("product_id"),
			Search:  r.URL.Query().Get("q"),
			Limit:   limit, Offset: offset,
		}
		lics, total, err := svc.Store.Q().ListLicenses(r.Context(), f)
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": lics, "total": total})
	}
}

func handleLicenseDetail(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chiURLParam(r, "id")
		lic, err := svc.Store.Q().GetLicense(r.Context(), id, false)
		if err != nil {
			MapError(w, r, err)
			return
		}
		if service.AgentScopeDenied(adminCtx(r), lic.AgentID) {
			ErrorWriter(w, r, nil, 404, "LICENSE_NOT_FOUND", "许可证不存在")
			return
		}
		devices, _ := svc.Store.Q().ListDevices(r.Context(), id, true)
		events, _ := svc.Store.Q().ListLicenseEvents(r.Context(), id, 50)
		online, _ := svc.Cache.OnlineDevices(r.Context(), id)
		writeJSON(w, 200, map[string]any{
			"license": lic, "devices": devices, "events": events, "online": online,
		})
	}
}

func handleLicenseAction(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action string `json:"action"`
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.LicenseAction(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Action, req.Reason, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleLicenseNote(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Note string `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.SetLicenseNote(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Note, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleListDevices(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		licID := r.URL.Query().Get("license_id")
		if licID == "" {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "license_id required")
			return
		}
		// agent 角色数据范围：许可证不属于本代理时按 404 处理（防枚举）
		if lic, err := svc.Store.Q().GetLicense(r.Context(), licID, false); err != nil {
			MapError(w, r, err)
			return
		} else if service.AgentScopeDenied(adminCtx(r), lic.AgentID) {
			ErrorWriter(w, r, nil, 404, "LICENSE_NOT_FOUND", "许可证不存在")
			return
		}
		devices, err := svc.Store.Q().ListDevices(r.Context(), licID, true)
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": devices})
	}
}

func handleUnbindDevice(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason string `json:"reason"`
		}
		_ = decodeJSON(r, &req)
		dev, err := svc.UnbindDevice(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Reason, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, dev)
	}
}

// ===== 代理商 / 管理员 / 审计 / 风控 / 统计 =====

func handleListAgents(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		as, err := svc.Store.Q().ListAgents(r.Context())
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": as})
	}
}

func handleCreateAgent(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name            string  `json:"name"`
			ParentID        *string `json:"parent_id"`
			AccountUsername string  `json:"account_username"`
			AccountPassword string  `json:"account_password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		a, account, err := svc.CreateAgent(r.Context(), adminCtx(r), req.Name, req.ParentID, req.AccountUsername, req.AccountPassword, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 201, struct {
			*store.Agent
			Account *service.AgentAccount `json:"account,omitempty"`
		}{a, account})
	}
}

// handleAgentProducts 查看/开通/收回代理商的产品权限（仅超管）。
func handleAgentProducts(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := chiURLParam(r, "id")
		switch r.Method {
		case http.MethodGet:
			ids, err := svc.ListAgentProductGrants(r.Context(), adminCtx(r), agentID)
			if err != nil {
				MapError(w, r, err)
				return
			}
			writeJSON(w, 200, map[string]any{"items": ids})
		case http.MethodPost:
			var req struct {
				ProductID string `json:"product_id"`
				Granted   bool   `json:"granted"`
			}
			if err := decodeJSON(r, &req); err != nil {
				ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
				return
			}
			if req.ProductID == "" {
				ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "product_id 必填")
				return
			}
			if err := svc.SetAgentProductGrant(r.Context(), adminCtx(r), agentID, req.ProductID, req.Granted, ClientIP(r), RequestID(r)); err != nil {
				MapError(w, r, err)
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true})
		default:
			ErrorWriter(w, r, nil, 405, "METHOD_NOT_ALLOWED", "不支持的请求方法")
		}
	}
}

// handleAgentAccount 查看/修改代理商登录账号（仅超管）。POST 支持改用户名与重置密码，
// 新密码仅在响应中出现一次；重置后该账号全部会话立即失效。
func handleAgentAccount(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := chiURLParam(r, "id")
		switch r.Method {
		case http.MethodGet:
			ad, err := svc.GetAgentAccount(r.Context(), adminCtx(r), agentID)
			if err != nil {
				MapError(w, r, err)
				return
			}
			writeJSON(w, 200, map[string]any{"username": ad.Username, "status": ad.Status})
		case http.MethodPost:
			var req struct {
				AdminID     string `json:"admin_id"`
				NewUsername string `json:"new_username"`
				NewPassword string `json:"new_password"`
			}
			if err := decodeJSON(r, &req); err != nil {
				ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
				return
			}
			if req.AdminID == "" {
				ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "admin_id 必填")
				return
			}
			if req.NewUsername == "" && req.NewPassword == "" {
				ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "用户名与新密码至少填一项")
				return
			}
			out, err := svc.UpdateAgentAccount(r.Context(), adminCtx(r), agentID, req.AdminID, strings.TrimSpace(req.NewUsername), req.NewPassword, ClientIP(r), RequestID(r))
			if err != nil {
				MapError(w, r, err)
				return
			}
			writeJSON(w, 200, out)
		default:
			ErrorWriter(w, r, nil, 405, "METHOD_NOT_ALLOWED", "不支持的请求方法")
		}
	}
}

func handleAgentBalance(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AmountYuan float64 `json:"amount_yuan"` // 元，正=充值，负=调差
			Note       string  `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if math.IsNaN(req.AmountYuan) || math.IsInf(req.AmountYuan, 0) || req.AmountYuan > 9_000_000_000 || req.AmountYuan < -9_000_000_000 {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "金额无效或超出范围")
			return
		}
		amountCents := int64(req.AmountYuan * 100)
		if amountCents == 0 {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "金额不能为 0")
			return
		}
		after, err := svc.AgentAdjustBalance(r.Context(), adminCtx(r), chiURLParam(r, "id"), amountCents, req.Note, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"balance_cents": after})
	}
}

func handleAgentTransactions(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txs, err := svc.Store.Q().ListAgentTransactions(r.Context(), chiURLParam(r, "id"), 100)
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": txs})
	}
}

func handleAgentStatus(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Status string `json:"status"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.AgentStatus(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Status, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleListAdmins(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		as, err := svc.Store.Q().ListAdmins(r.Context())
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": as})
	}
}

func handleCreateAdmin(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username    string  `json:"username"`
			DisplayName string  `json:"display_name"`
			Password    string  `json:"password"`
			Role        string  `json:"role"`
			AgentID     *string `json:"agent_id"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		a, err := svc.CreateAdmin(r.Context(), adminCtx(r), req.Username, req.DisplayName,
			req.Password, req.Role, req.AgentID, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 201, a)
	}
}

func handleAdminStatus(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Status string `json:"status"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.SetAdminStatus(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Status, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleListAudit(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset := pageParams(r)
		var since *time.Time
		if v := r.URL.Query().Get("since"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				since = &t
			}
		}
		f := store.AuditFilter{
			AdminID: r.URL.Query().Get("admin_id"),
			Action:  r.URL.Query().Get("action"),
			Target:  r.URL.Query().Get("target"),
			Since:   since,
			Limit:   limit, Offset: offset,
		}
		logs, total, err := svc.Store.Q().ListAudit(r.Context(), f)
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": logs, "total": total})
	}
}

func handleListRisk(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events, err := svc.Store.Q().ListRiskEvents(r.Context(), store.RiskFilter{
			Kind:  r.URL.Query().Get("kind"),
			Limit: 200,
		})
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": events})
	}
}

func handleListBans(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bans, err := svc.Store.Q().ListBans(r.Context())
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": bans})
	}
}

func handleCreateBan(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Kind   string `json:"kind"`
			Value  string `json:"value"`
			Reason string `json:"reason"`
			Until  string `json:"until"` // RFC3339，可选
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		var until *time.Time
		if req.Until != "" {
			if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
				until = &t
			}
		}
		b, err := svc.CreateBan(r.Context(), adminCtx(r), req.Kind, req.Value, req.Reason, until, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 201, b)
	}
}

func handleDeleteBan(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.DeleteBan(r.Context(), adminCtx(r), req.Kind, req.Value, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleKeys(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kex, err := svc.Store.Q().ActiveKexKeys(r.Context())
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"kex_keys":  kex,
			"sign_kids": svc.Keys.AllKIDs(),
			"active":    svc.Keys.ActiveKID(),
		})
	}
}

func handleStats(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, err := svc.Stats(r.Context())
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, st)
	}
}

// ===== 工具 =====

// errBadEncoding 标记请求体编码错误（非 UTF-8 / 含 U+FFFD）。
// Go 的 json 解码器会把无效 UTF-8 静默替换成 U+FFFD 存库——必须拒绝而非容忍，
// 否则 GBK 客户端会造成不可逆的数据损坏。
var errBadEncoding = errors.New("request body is not valid UTF-8")

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if !utf8.Valid(body) || bytes.ContainsRune(body, utf8.RuneError) {
		return errBadEncoding
	}
	dec := newJSONDecoder(bytes.NewReader(body))
	return dec.Decode(v)
}

func pageParams(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
