package httpapi

import (
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/domain"
	"github.com/vertify/license-platform/internal/service"
)

// ClientRouter 公开客户端 API（/v1）。所有端点限流 + 严格体积限制。
// 接口限流阈值可后台配置（api_rate_limits 表，30s 缓存），未配置时用环境变量默认值。
func ClientRouter(svc *service.Services, trustedProxies []*net.IPNet) http.Handler {
	r := chi.NewRouter()
	limiter := NewScopeRateLimiter(svc)
	r.Use(RealIP(trustedProxies), Recover, RequestIDMiddleware, LogAccess, SecurityHeaders)

	r.Group(func(r chi.Router) {
		r.Use(limiter.Middleware("bootstrap", svc.Cfg.BootstrapRatelimitPerMin))
		r.Get("/v1/bootstrap", handleBootstrap(svc))
	})

	r.Group(func(r chi.Router) {
		r.Use(BodyLimit(64 << 10))
		r.Use(limiter.Middleware("activate", svc.Cfg.ActivateRatelimitPerMin))
		r.Post("/v1/activate", handleActivate(svc))
		r.Post("/v1/redeem", handleRedeem(svc))
	})

	r.Group(func(r chi.Router) {
		r.Use(BodyLimit(8 << 10))
		r.Use(limiter.Middleware("heartbeat", svc.Cfg.HeartbeatRatelimitPerMin))
		r.Post("/v1/heartbeat", handleHeartbeat(svc))
		r.Post("/v1/deactivate", handleDeactivate(svc))
	})

	// 终端用户账号 API（账号制模式）
	r.Group(func(r chi.Router) {
		r.Use(BodyLimit(4 << 10))
		r.Use(limiter.Middleware("user_register", 3))
		r.Post("/v1/user/register", handleUserRegister(svc))
	})
	r.Group(func(r chi.Router) {
		r.Use(BodyLimit(4 << 10))
		r.Use(limiter.Middleware("user_login", 10))
		r.Post("/v1/user/login", handleUserLogin(svc))
	})
	r.Group(func(r chi.Router) {
		r.Use(BodyLimit(4 << 10))
		r.Use(limiter.Middleware("user_ops", 30))
		r.Post("/v1/user/bindcard", handleUserBindCard(svc))
		r.Post("/v1/user/changepw", handleUserChangePw(svc))
		r.Post("/v1/user/recover", handleUserRecover(svc))
	})

	r.Group(func(r chi.Router) {
		r.Use(limiter.Middleware("bootstrap", svc.Cfg.BootstrapRatelimitPerMin))
		r.Get("/v1/announce", handleAnnounce(svc))
	})
	return r
}

// bootstrapResponse 客户端引导信息：KEX 公钥（信封加密用）与签名公钥（验签锚）。
// 客户端 SDK 内嵌公钥集合做首选校验，此接口用于轮换窗口期的补充发现。
type bootstrapResponse struct {
	Protocol   int               `json:"protocol"`
	ServerTime int64             `json:"server_time"`
	KexKeys    []map[string]any  `json:"kex_keys"`
	SignKeys   map[string]string `json:"sign_keys"`
	Policy     map[string]any    `json:"policy"`
}

func handleBootstrap(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 封禁检查
		if banned, _ := svc.Store.Q().IsBanned(r.Context(), "ip", ClientIP(r)); banned {
			ErrorWriter(w, r, nil, 403, "BANNED", "已被策略拦截")
			return
		}
		kex, err := svc.Store.Q().ActiveKexKeys(r.Context())
		if err != nil {
			MapError(w, r, err)
			return
		}
		resp := bootstrapResponse{
			Protocol:   1,
			ServerTime: time.Now().Unix(),
			KexKeys:    kex,
			SignKeys:   crypto.PublicKeysSnapshot(svc.Keys),
			Policy: map[string]any{
				"replay_window_seconds":  int(svc.Cfg.ReplayWindow.Seconds()),
				"max_clock_skew_seconds": int(svc.Cfg.MaxClockSkew.Seconds()),
			},
		}
		writeJSON(w, 200, resp)
	}
}

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty body")
	}
	return b, nil
}

func parseDeviceAuth(r *http.Request) (*service.DeviceSignature, error) {
	h := r.Header.Get("X-Vft-Device-Auth")
	if h == "" {
		return nil, errEnvelope // 归一为 400 协议错误
	}
	return service.ParseDeviceSignature(h)
}

func handleActivate(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		ds, err := parseDeviceAuth(r)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "缺少设备签名")
			return
		}
		ip := ClientIP(r)
		if os.Getenv("VFT_DEBUG") == "1" {
			sum := sha256.Sum256(body)
			log.Printf("[dbg] activate body len=%d sha256=%x hdr=%s", len(body), sum, r.Header.Get("X-Vft-Device-Auth"))
		}
		if banned, _ := svc.Store.Q().IsBanned(r.Context(), "ip", ip); banned {
			ErrorWriter(w, r, nil, 403, "BANNED", "已被策略拦截")
			return
		}
		res, err := svc.Activate(r.Context(), body, ds, ip, RequestID(r))
		if err != nil {
			// 卡密不存在/格式错误计入枚举检测（连续失败触发 IP 级限流）
			if errors.Is(err, domain.ErrCardNotFound) || errors.Is(err, domain.ErrCardInvalidFormat) {
				if svc.Risk.CardFailure(r.Context(), ip) {
					ErrorWriter(w, r, nil, 429, "RATE_LIMITED", "请求过于频繁")
					return
				}
			}
			MapError(w, r, err)
			return
		}
		lease, err := svc.MintLease(res.LeaseClaims)
		if err != nil {
			MapError(w, r, err)
			return
		}
		res.Lease = lease
		writeJSON(w, 200, res)
	}
}

func handleHeartbeat(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		ds, err := parseDeviceAuth(r)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "缺少设备签名")
			return
		}
		res, err := svc.Heartbeat(r.Context(), ds, body, ClientIP(r))
		if err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, res)
	}
}

func handleRedeem(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		ds, err := parseDeviceAuth(r)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "缺少设备签名")
			return
		}
		ip := ClientIP(r)
		if banned, _ := svc.Store.Q().IsBanned(r.Context(), "ip", ip); banned {
			ErrorWriter(w, r, nil, 403, "BANNED", "已被策略拦截")
			return
		}
		res, err := svc.Redeem(r.Context(), body, ds, ip, RequestID(r))
		if err != nil {
			if (errors.Is(err, domain.ErrCardNotFound) || errors.Is(err, domain.ErrCardInvalidFormat)) &&
				svc.Risk.CardFailure(r.Context(), ip) {
				ErrorWriter(w, r, nil, 429, "RATE_LIMITED", "请求过于频繁")
				return
			}
			MapError(w, r, err)
			return
		}
		lease, err := svc.MintLease(res.LeaseClaims)
		if err != nil {
			MapError(w, r, err)
			return
		}
		res.Lease = lease
		writeJSON(w, 200, res)
	}
}

func handleDeactivate(svc *service.Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "请求体无效")
			return
		}
		ds, err := parseDeviceAuth(r)
		if err != nil {
			ErrorWriter(w, r, nil, 400, "BAD_REQUEST", "缺少设备签名")
			return
		}
		if err := svc.Deactivate(r.Context(), ds, body, ClientIP(r), RequestID(r)); err != nil {
			MapError(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

var _ = chi.URLParam // keep import parity
