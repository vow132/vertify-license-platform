// 管理端点：终端用户管理、公告、版本、接口限流、批量卡密操作。
package httpapi

import (
	"net/http"
	"strconv"

	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/service"
	"github.com/vertify/license-platform/internal/store"
)

func parseID(s string) (int64, bool) {
	id, err := strconv.ParseInt(s, 10, 64)
	return id, err == nil && id > 0
}

// ===== 终端用户管理 =====

func handleListUsers(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset := pageParams(r)
		users, total, err := svc.Store.Q().ListEndUsers(r.Context(), store.EndUserFilter{
			ProductID: r.URL.Query().Get("product_id"),
			Status:    r.URL.Query().Get("status"),
			Search:    r.URL.Query().Get("q"),
			Limit:     limit, Offset: offset,
		})
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": users, "total": total})
	}
}

func handleUserDetail(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chiURLParam(r, "id")
		u, err := svc.Store.Q().GetEndUser(r.Context(), id)
		if err != nil {
			MapError(w, r, err)
			return
		}
		logs, err := svc.Store.Q().ListEndUserLogs(r.Context(), id, 100)
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"user": u, "logs": logs})
	}
}

func handleUserAction(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action string `json:"action"` // disable | enable | reset-machine | extend
			Days   int    `json:"days"`
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		id := chiURLParam(r, "id")
		if _, err := svc.Store.Q().GetEndUser(r.Context(), id); err != nil {
			MapError(w, r, err)
			return
		}
		ac := adminCtx(r)
		var err error
		switch req.Action {
		case "disable":
			err = svc.Store.Q().SetEndUserStatus(r.Context(), id, "disabled")
		case "enable":
			err = svc.Store.Q().SetEndUserStatus(r.Context(), id, "active")
		case "reset-machine":
			err = svc.Store.Q().ResetEndUserMachine(r.Context(), id)
		case "extend":
			if req.Days <= 0 || req.Days > 36500 {
				ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "天数无效")
				return
			}
			_, err = svc.Store.Q().ExtendEndUser(r.Context(), id, req.Days)
		default:
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "未知操作")
			return
		}
		if err != nil {
			MapError(w, r, err)
			return
		}
		svc.Audit(r.Context(), ac, "user."+req.Action, "end_user", id, nil,
			map[string]any{"days": req.Days, "reason": req.Reason}, nil, ClientIP(r), RequestID(r))
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// ===== 批量卡密操作 =====

func handleBulkCardAction(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IDs    []string `json:"ids"`
			Action string   `json:"action"` // freeze | unfreeze | revoke
			Reason string   `json:"reason"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if len(req.IDs) == 0 || len(req.IDs) > 100 {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "ids 数量需在 1-100 之间")
			return
		}
		if req.Reason == "" && (req.Action == "freeze" || req.Action == "revoke") {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "冻结/吊销需填写原因")
			return
		}
		ok, failed := 0, map[string]string{}
		for _, id := range req.IDs {
			if err := svc.CardAction(r.Context(), adminCtx(r), id, req.Action, req.Reason, ClientIP(r), RequestID(r)); err != nil {
				failed[id] = err.Error()
				continue
			}
			ok++
		}
		writeJSON(w, 200, map[string]any{"ok": ok, "failed": failed})
	}
}

// ===== 软件公告 =====

func handleListMessages(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs, err := svc.Store.Q().ListSoftMessages(r.Context(), r.URL.Query().Get("product_id"))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": msgs})
	}
}

func handleCreateMessage(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ProductID string `json:"product_id"`
			Content   string `json:"content"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if req.ProductID == "" || len(req.Content) == 0 || len(req.Content) > 2000 {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "参数无效")
			return
		}
		msg, err := svc.Store.Q().CreateSoftMessage(r.Context(), req.ProductID, req.Content, adminCtx(r).Admin.ID)
		if err != nil {
			MapError(w, r, err)
			return
		}
		svc.Audit(r.Context(), adminCtx(r), "message.create", "product", req.ProductID, nil, msg, nil, ClientIP(r), RequestID(r))
		writeJSON(w, 201, msg)
	}
}

func handleSetMessageEnabled(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		mid, valid := parseID(chiURLParam(r, "id"))
		if !valid {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "ID 无效")
			return
		}
		if err := svc.Store.Q().SetSoftMessageEnabled(r.Context(), mid, req.Enabled); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleDeleteMessage(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mid, valid := parseID(chiURLParam(r, "id"))
		if !valid {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "ID 无效")
			return
		}
		if err := svc.Store.Q().DeleteSoftMessage(r.Context(), mid); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// ===== 软件版本 =====

func handleListVersions(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vs, err := svc.Store.Q().ListProductVersions(r.Context(), r.URL.Query().Get("product_id"))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": vs})
	}
}

func handleCreateVersion(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ProductID   string `json:"product_id"`
			Version     string `json:"version"`
			DownloadURL string `json:"download_url"`
			Notes       string `json:"notes"`
			ForceUpdate bool   `json:"force_update"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if req.ProductID == "" || req.Version == "" || req.DownloadURL == "" {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "参数无效")
			return
		}
		v, err := svc.Store.Q().CreateProductVersion(r.Context(), req.ProductID, req.Version, req.DownloadURL, req.Notes, req.ForceUpdate)
		if err != nil {
			MapError(w, r, err)
			return
		}
		svc.Audit(r.Context(), adminCtx(r), "version.create", "product", req.ProductID, nil, v, nil, ClientIP(r), RequestID(r))
		writeJSON(w, 201, v)
	}
}

func handleDeleteVersion(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mid, valid := parseID(chiURLParam(r, "id"))
		if !valid {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "ID 无效")
			return
		}
		if err := svc.Store.Q().DeleteProductVersion(r.Context(), mid); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// ===== 接口限流配置 =====

// 已知限流 scope 与默认值（前端下拉展示）。
var knownRateLimitScopes = []string{
	"bootstrap", "activate", "heartbeat", "redeem", "user_login", "user_register", "user_ops",
}

func handleListRateLimits(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conf, err := svc.Store.Q().AllApiRateLimits(r.Context())
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"scopes": knownRateLimitScopes,
			"config": conf,
			"defaults": map[string]int{
				"bootstrap":     svc.Cfg.BootstrapRatelimitPerMin,
				"activate":      svc.Cfg.ActivateRatelimitPerMin,
				"heartbeat":     svc.Cfg.HeartbeatRatelimitPerMin,
				"redeem":        svc.Cfg.ActivateRatelimitPerMin,
				"user_login":    10,
				"user_register": 3,
				"user_ops":      30,
			},
		})
	}
}

func handleSetRateLimit(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Scope       string `json:"scope"`
			LimitPerMin int    `json:"limit_per_min"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		known := false
		for _, s := range knownRateLimitScopes {
			if s == req.Scope {
				known = true
			}
		}
		if !known || req.LimitPerMin < 1 || req.LimitPerMin > 100000 {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "scope 或阈值无效")
			return
		}
		if err := svc.Store.Q().UpsertApiRateLimit(r.Context(), req.Scope, req.LimitPerMin); err != nil {
			MapError(w, r, err)
			return
		}
		svc.Audit(r.Context(), adminCtx(r), "ratelimit.set", "api", req.Scope, nil,
			map[string]any{"limit_per_min": req.LimitPerMin}, nil, ClientIP(r), RequestID(r))
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// ===== 卡密备注 / 许可证手动续期 =====

func handleRevealCard(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		card, err := svc.Store.Q().GetCardByID(r.Context(), chiURLParam(r, "id"))
		if err != nil {
			MapError(w, r, err)
			return
		}
		if service.AgentScopeDenied(adminCtx(r), card.AgentID) {
			ErrorWriter(w, r, nil, 404, "CARD_NOT_FOUND", "卡密不存在")
			return
		}
		if len(card.SecretCiphertext) == 0 || len(card.SecretNonce) == 0 || card.SecretKeyVersion == "" {
			ErrorWriter(w, r, nil, 409, "CARD_SECRET_UNAVAILABLE", "此卡生成时未保存可恢复卡号")
			return
		}
		secret, err := svc.DecryptCardSecret(card.ID, card.BatchID, card.ProductID, card.SecretCiphertext, card.SecretNonce, card.SecretKeyVersion)
		if err != nil {
			ErrorWriter(w, r, nil, 500, "CARD_SECRET_ERROR", "卡密解密失败")
			return
		}
		normalized, err := crypto.NormalizeCard(secret)
		if err != nil || svc.CardLookup(normalized) != card.Lookup {
			ErrorWriter(w, r, nil, 500, "CARD_SECRET_MISMATCH", "卡密密文与索引不一致")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		svc.Audit(r.Context(), adminCtx(r), "card.reveal", "card", card.ID, nil, map[string]any{"prefix": card.Prefix}, nil, ClientIP(r), RequestID(r))
		writeJSON(w, 200, map[string]any{"card": crypto.FormatCard(secret)})
	}
}
func handleSetCardNote(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Note string `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.SetCardNote(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Note, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleExtendLicense(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Days   int    `json:"days"`
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		newExp, err := svc.AdminExtendLicense(r.Context(), adminCtx(r), chiURLParam(r, "id"), req.Days, req.Reason, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"new_expiry": newExp})
	}
}
