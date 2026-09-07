// Package config 从环境变量加载全部配置（12-factor）。
// 任何密钥类配置缺失时启动失败——绝不提供硬编码默认密钥。
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// SigningKey 一对 Ed25519 签名密钥（kid → base64url seed）。
type SigningKey struct {
	KID  string
	Seed []byte
}

// KexKey 服务端信封加密 X25519 私钥。
type KexKey struct {
	KID      string
	PrivSeed []byte // 32B raw
	Active   bool
}

// Config 全部运行时配置。
type Config struct {
	Env string // dev | staging | prod

	ClientAddr  string // 公开客户端 API 监听
	AdminAddr   string // 管理面监听（与公开 API 隔离）
	MetricsAddr string

	DatabaseURL string
	RedisURL    string

	SigningKeys   []SigningKey
	SigningActive string
	KexKeys       []KexKey

	CardHMACKey   []byte // ≥32B，卡密检索 HMAC
	CardEncKeys   map[string][]byte
	CardEncActive string

	AdminSessionTTL time.Duration
	CookieSecure    bool

	// 首次初始化管理员（仅当 admins 表为空时生效）
	InitialAdminUser     string
	InitialAdminPassword string
	InitialAdminOTP      string // 可选预置 TOTP 密钥

	// 客户端 API 防护
	ActivateRatelimitPerMin  int // 每 IP 每分钟激活请求
	AdminLoginRPM            int // 管理面登录 IP 限流
	HeartbeatRatelimitPerMin int
	BootstrapRatelimitPerMin int
	ReplayWindow             time.Duration // nonce 重放窗口
	MaxClockSkew             time.Duration // 设备签名时间戳容差
	TrustedProxies           []*net.IPNet  // 可信代理网段（仅这些来源的 XFF 头被采信）

	// 设备签名序列号：超过该数量在 Redis 未命中时回查 DB
	GracefulShutdown time.Duration

	LogLevel string

	TLSCertFile string // 客户端面 TLS 证书（可选；生产建议网关终结 TLS）
	TLSKeyFile  string
}

func fromEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("config: required env %s is not set", key)
	}
	return v, nil
}

// Load 读取并校验全部配置。
func Load() (*Config, error) {
	c := &Config{
		Env:                  fromEnv("VFT_ENV", "dev"),
		ClientAddr:           fromEnv("VFT_CLIENT_ADDR", ":8080"),
		AdminAddr:            fromEnv("VFT_ADMIN_ADDR", ":8081"),
		MetricsAddr:          fromEnv("VFT_METRICS_ADDR", ":9090"),
		DatabaseURL:          fromEnv("VFT_DATABASE_URL", "postgres://vertify:vertify@127.0.0.1:54329/vertify?sslmode=disable"),
		RedisURL:             fromEnv("VFT_REDIS_URL", "redis://127.0.0.1:6399/0"),
		GracefulShutdown:     15 * time.Second,
		LogLevel:             fromEnv("VFT_LOG_LEVEL", "info"),
		InitialAdminUser:     os.Getenv("VFT_INITIAL_ADMIN_USER"),
		InitialAdminPassword: os.Getenv("VFT_INITIAL_ADMIN_PASSWORD"),
		InitialAdminOTP:      os.Getenv("VFT_INITIAL_ADMIN_TOTP"),
		TLSCertFile:          os.Getenv("VFT_TLS_CERT"),
		TLSKeyFile:           os.Getenv("VFT_TLS_KEY"),
	}
	if c.Env == "prod" {
		if os.Getenv("VFT_SIGNER_PROVIDER") != "kms" {
			return nil, errors.New("config: prod requires VFT_SIGNER_PROVIDER=kms; LocalSigner seed mode is disabled")
		}
		if os.Getenv("VFT_TRUSTED_PROXIES") == "" {
			return nil, errors.New("config: prod requires VFT_TRUSTED_PROXIES")
		}

		for _, k := range []string{"VFT_DATABASE_URL", "VFT_REDIS_URL"} {
			if os.Getenv(k) == "" {
				return nil, fmt.Errorf("config: %s required in prod", k)
			}
		}
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			if os.Getenv("VFT_TRUSTED_TLS_PROXY") != "true" {
				return nil, errors.New("config: prod requires VFT_TLS_CERT/VFT_TLS_KEY or VFT_TRUSTED_TLS_PROXY=true")
			}
		}

		c.CookieSecure = true
	} else {
		c.CookieSecure = os.Getenv("VFT_COOKIE_SECURE") == "true"
	}

	var err error
	activeKID := os.Getenv("VFT_SIGN_ACTIVE_KID")
	if c.SigningKeys, err = parseSigningKeys(os.Getenv("VFT_SIGN_KEYS"), activeKID); err != nil {
		return nil, err
	}
	c.SigningActive = activeKID
	if c.KexKeys, err = parseKexKeys(os.Getenv("VFT_KEX_KEYS")); err != nil {
		return nil, err
	}
	if len(c.KexKeys) == 0 || !anyActive(c.KexKeys) {
		return nil, errors.New("config: VFT_KEX_KEYS must contain at least one active key")
	}
	hmacB64, err := mustEnv("VFT_CARD_HMAC_KEY")
	if err != nil {
		return nil, err
	}
	c.CardHMACKey, err = base64.RawURLEncoding.DecodeString(hmacB64)
	if err != nil || len(c.CardHMACKey) < 32 {
		return nil, errors.New("config: VFT_CARD_HMAC_KEY must be >=32 bytes base64url")
	}
	encKeys, activeEnc, err := parseCardEncKeys(os.Getenv("VFT_CARD_ENC_KEYS"), os.Getenv("VFT_CARD_ENC_ACTIVE_KID"))
	if err != nil {
		return nil, err
	}
	c.CardEncKeys, c.CardEncActive = encKeys, activeEnc

	c.AdminSessionTTL = durEnv("VFT_ADMIN_SESSION_TTL", 8*time.Hour)
	c.ReplayWindow = durEnv("VFT_REPLAY_WINDOW", 5*time.Minute)
	c.MaxClockSkew = durEnv("VFT_MAX_CLOCK_SKEW", 120*time.Second)
	c.ActivateRatelimitPerMin = intEnv("VFT_ACTIVATE_RPM", 10)
	c.AdminLoginRPM = intEnv("VFT_ADMIN_LOGIN_RPM", 10)
	c.HeartbeatRatelimitPerMin = intEnv("VFT_HEARTBEAT_RPM", 30)
	c.BootstrapRatelimitPerMin = intEnv("VFT_BOOTSTRAP_RPM", 60)
	c.TLSCertFile = os.Getenv("VFT_TLS_CERT")
	c.TLSKeyFile = os.Getenv("VFT_TLS_KEY")

	// 可信代理网段：反代/网关后部署必须配置（如 10.0.0.0/8），否则 XFF 不被采信
	if spec := os.Getenv("VFT_TRUSTED_PROXIES"); spec != "" {
		for _, cidr := range strings.Split(spec, ",") {
			cidr = strings.TrimSpace(cidr)
			if !strings.Contains(cidr, "/") {
				cidr += "/32"
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("config: bad VFT_TRUSTED_PROXIES %q: %w", cidr, err)
			}
			c.TrustedProxies = append(c.TrustedProxies, ipnet)
		}
	}
	return c, nil
}

func parseCardEncKeys(spec, active string) (map[string][]byte, string, error) {
	out := map[string][]byte{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			return nil, "", errors.New("config: bad VFT_CARD_ENC_KEYS")
		}
		kid := parts[0]
		raw := strings.TrimSuffix(parts[1], "*")
		b, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(b) != 32 {
			return nil, "", errors.New("config: card encryption keys must be 32 bytes base64url")
		}
		out[kid] = b
		if strings.HasSuffix(parts[1], "*") && active == "" {
			active = kid
		}
	}
	if len(out) == 0 {
		return nil, "", errors.New("config: VFT_CARD_ENC_KEYS is required")
	}
	if _, ok := out[active]; !ok {
		return nil, "", errors.New("config: active card encryption key not found")
	}
	return out, active, nil
}
func durEnv(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func intEnv(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// parseSigningKeys: "kid1:<seedb64>,kid2:<seedb64>"
func parseSigningKeys(spec, active string) ([]SigningKey, error) {
	if spec == "" {
		return nil, errors.New("config: VFT_SIGN_KEYS required (kid:base64url-seed pairs)")
	}
	if active == "" {
		return nil, errors.New("config: VFT_SIGN_ACTIVE_KID required")
	}
	var keys []SigningKey
	for _, part := range strings.Split(spec, ",") {
		kid, seed, found := strings.Cut(strings.TrimSpace(part), ":")
		if !found || kid == "" || seed == "" {
			return nil, fmt.Errorf("config: bad VFT_SIGN_KEYS segment %q", part)
		}
		raw, err := base64.RawURLEncoding.DecodeString(seed)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("config: kid %s seed must be 32B base64url", kid)
		}
		keys = append(keys, SigningKey{KID: kid, Seed: raw})
	}
	for _, k := range keys {
		if k.KID == active {
			return keys, nil
		}
	}
	return nil, fmt.Errorf("config: active kid %q not in VFT_SIGN_KEYS", active)
}

// parseKexKeys: "kid1:<seedb64>[*],kid2:<seedb64>"（* 标记 active）
func parseKexKeys(spec string) ([]KexKey, error) {
	if spec == "" {
		return nil, errors.New("config: VFT_KEX_KEYS required")
	}
	var keys []KexKey
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		active := strings.HasSuffix(part, "*")
		part = strings.TrimSuffix(part, "*")
		kid, seed, found := strings.Cut(part, ":")
		if !found || kid == "" || seed == "" {
			return nil, fmt.Errorf("config: bad VFT_KEX_KEYS segment %q", part)
		}
		raw, err := base64.RawURLEncoding.DecodeString(seed)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("config: kex kid %s seed must be 32B base64url", kid)
		}
		keys = append(keys, KexKey{KID: kid, PrivSeed: raw, Active: active})
	}
	return keys, nil
}

func anyActive(keys []KexKey) bool {
	for _, k := range keys {
		if k.Active {
			return true
		}
	}
	return false
}
