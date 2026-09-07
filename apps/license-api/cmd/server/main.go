// server 启动授权 API：公开客户端面 + 管理面 + 指标端口。
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/vertify/license-platform/internal/cache"
	"github.com/vertify/license-platform/internal/config"
	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/httpapi"
	"github.com/vertify/license-platform/internal/service"
	"github.com/vertify/license-platform/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	// 数据库迁移默认开启，生产可由独立 Job 执行后设置 VFT_SKIP_MIGRATE=true。
	if os.Getenv("VFT_SKIP_MIGRATE") != "true" {
		if err := store.Migrate(ctx, cfg.DatabaseURL, findMigrationsDir()); err != nil {
			slog.Error("migrate", "err", err)
			os.Exit(1)
		}
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	ca, err := cache.New(ctx, cfg.RedisURL)
	if err != nil {
		slog.Error("cache", "err", err)
		os.Exit(1)
	}
	defer ca.Close()

	// 签名密钥（生产应由 KMS 提供 crypto.Signer 实现；本地实现仅开发/测试）
	keyMap := map[string]string{}
	for _, k := range cfg.SigningKeys {
		keyMap[k.KID] = base64.RawURLEncoding.EncodeToString(k.Seed)
	}
	signer, err := crypto.NewLocalSigner(keyMap, cfg.SigningActive)
	if err != nil {
		slog.Error("signer", "err", err)
		os.Exit(1)
	}
	_ = ed25519.PublicKeySize // 保留下方引用校验

	// 信封加密 KEX 密钥
	var kexPairs []*crypto.KexKeyPair
	for _, k := range cfg.KexKeys {
		pair, err := crypto.NewKexKeyPairFromSeed(k.KID, k.PrivSeed)
		if err != nil {
			slog.Error("kex", "err", err)
			os.Exit(1)
		}
		pair.Active = k.Active
		kexPairs = append(kexPairs, pair)
		if err := st.Q().UpsertKexKey(ctx, pair.KID, pair.PubB64, "A256GCM", pair.Active); err != nil {
			slog.Error("kex upsert", "err", err)
			os.Exit(1)
		}
	}

	svc, err := service.New(cfg, signer, kexPairs, st, ca)
	if err != nil {
		slog.Error("service", "err", err)
		os.Exit(1)
	}

	// 部署陷阱预警：反代后未配置可信网段 → XFF 不被采信，全部客户端共享代理 IP，
	// 限流/封禁/枚举检测将把所有用户聚合为一个主体。
	if cfg.Env == "prod" && len(cfg.TrustedProxies) == 0 {
		slog.Warn("VFT_TRUSTED_PROXIES is empty in prod: X-Forwarded-For is not trusted; " +
			"rate limiting and bans will aggregate all clients behind a proxy into one identity")
	}

	if err := ensureInitialAdmin(ctx, svc); err != nil {
		slog.Error("initial admin", "err", err)
		os.Exit(1)
	}

	clientSrv := &http.Server{
		Addr: cfg.ClientAddr, Handler: httpapi.ClientRouter(svc, cfg.TrustedProxies),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	adminSrv := &http.Server{
		Addr: cfg.AdminAddr, Handler: httpapi.AdminRouter(svc, cfg.TrustedProxies),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	metricsSrv := &http.Server{
		Addr: cfg.MetricsAddr, Handler: promhttp.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("client api listening", "addr", cfg.ClientAddr, "tls", cfg.TLSCertFile != "")
		var err error
		if cfg.Env == "prod" && cfg.TLSCertFile == "" && os.Getenv("VFT_TRUSTED_TLS_PROXY") != "true" {
			slog.Error("production requires client TLS or a trusted TLS proxy")
			os.Exit(1)
		}
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			err = clientSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = clientSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			slog.Error("client api stopped", "err", err)
			os.Exit(1)
		}
	}()
	go func() { slog.Info("admin api listening", "addr", cfg.AdminAddr); _ = adminSrv.ListenAndServe() }()
	go func() { slog.Info("metrics listening", "addr", cfg.MetricsAddr); _ = metricsSrv.ListenAndServe() }()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.GracefulShutdown)
	defer cancel()
	_ = clientSrv.Shutdown(shutdownCtx)
	_ = adminSrv.Shutdown(shutdownCtx)
	_ = metricsSrv.Shutdown(shutdownCtx)
}

func findMigrationsDir() string {
	for _, c := range []string{"/db/migrations", "../../db/migrations", "../../../db/migrations", "db/migrations"} {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return "../../db/migrations"
}

// ensureInitialAdmin 仅当 admins 表为空时创建初始管理员（口令来自环境变量）。
func ensureInitialAdmin(ctx context.Context, svc *service.Services) error {
	n, err := svc.Store.Q().CountAdmins(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if svc.Cfg.InitialAdminUser == "" || svc.Cfg.InitialAdminPassword == "" {
		return errors.New("no admins exist; set VFT_INITIAL_ADMIN_USER / VFT_INITIAL_ADMIN_PASSWORD to bootstrap")
	}
	admin, err := svc.BootstrapAdmin(ctx, svc.Cfg.InitialAdminUser, svc.Cfg.InitialAdminPassword, svc.Cfg.InitialAdminOTP)
	if err != nil {
		return err
	}
	slog.Warn("initial admin created — change password immediately", "username", admin.Username)
	return nil
}
