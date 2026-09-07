// 终端用户账号 API（/v1/user/*）：注册/登录/绑卡/改密/找回 + 公告/版本下发。
package httpapi

import (
	"errors"
	"net/http"

	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/service"
)

type userReq struct {
	Product      string   `json:"product"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	SecurityCode string   `json:"security_code"`
	NewPassword  string   `json:"new_password"`
	Token        string   `json:"token"`
	Card         string   `json:"card"`
	Components   []string `json:"components"`
}

func handleUserRegister(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req userReq
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.UserRegister(r.Context(), req.Product, req.Username, req.Password, req.SecurityCode, ClientIP(r), RequestID(r)); err != nil {
			if errors.Is(err, domain.ErrUserExists) && svc.Risk.UserSignupBurst(r.Context(), ClientIP(r)) {
				ErrorWriter(w, r, nil, 429, "RATE_LIMITED", "请求过于频繁")
				return
			}
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleUserLogin(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req userReq
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if banned, _ := svc.Store.Q().IsBanned(r.Context(), "ip", ClientIP(r)); banned {
			ErrorWriter(w, r, nil, 403, "BANNED", "已被策略拦截")
			return
		}
		res, err := svc.UserLogin(r.Context(), req.Product, req.Username, req.Password, req.Components, ClientIP(r), RequestID(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, res)
	}
}

func handleUserBindCard(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req userReq
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		ip := ClientIP(r)
		if banned, _ := svc.Store.Q().IsBanned(r.Context(), "ip", ip); banned {
			ErrorWriter(w, r, nil, 403, "BANNED", "已被策略拦截")
			return
		}
		newExp, err := svc.UserBindCard(r.Context(), req.Token, req.Card, ip, RequestID(r))
		if err != nil {
			if errors.Is(err, domain.ErrCardNotFound) && svc.Risk.CardFailure(r.Context(), ip) {
				ErrorWriter(w, r, nil, 429, "RATE_LIMITED", "请求过于频繁")
				return
			}
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "expires_at": newExp})
	}
}

func handleUserChangePw(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req userReq
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.UserChangePassword(r.Context(), req.Token, req.Password, req.NewPassword); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func handleUserRecover(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req userReq
		if err := decodeJSON(r, &req); err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		if err := svc.UserRecover(r.Context(), req.Product, req.Username, req.SecurityCode, req.NewPassword, ClientIP(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// handleAnnounce 公告 + 最新版本（公开，产品代码定位）。
func handleAnnounce(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		productCode := r.URL.Query().Get("product")
		if productCode == "" {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "product required")
			return
		}
		productID, err := svc.GetProductIDByCode(r.Context(), productCode)
		if err != nil {
			ErrorWriter(w, r, nil, 404, "PRODUCT_NOT_FOUND", "产品不存在")
			return
		}
		msg, _ := svc.Store.Q().LatestEnabledMessage(r.Context(), productID)
		var version any
		if v, verr := svc.Store.Q().LatestProductVersion(r.Context(), productID); verr == nil {
			version = v
		}
		writeJSON(w, 200, map[string]any{"message": msg, "version": version})
	}
}
