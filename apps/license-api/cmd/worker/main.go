// worker 后台任务：过期会话清理、到期许可证事件补记。
// 任务幂等，多副本部署安全（数据库原子操作保证不重复）。
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vertify/license-platform/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbURL := os.Getenv("VFT_DATABASE_URL")
	if dbURL == "" {
		slog.Error("VFT_DATABASE_URL required")
		os.Exit(1)
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		slog.Error("store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	slog.Info("worker started")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("worker stopped")
			return
		case <-ticker.C:
			runSweep(ctx, st)
		}
	}
}

func runSweep(ctx context.Context, st *store.Store) {
	// 1. 过期管理员会话清理（expires_at 超 7 天的行）
	if n, err := st.Q().ReapSessions(ctx); err != nil {
		slog.Warn("reap sessions failed", "err", err)
	} else if n > 0 {
		slog.Info("reaped sessions", "count", n)
	}

	// 2. 到期许可证 expired 事件补记（幂等：NOT EXISTS 防重复）。
	//    许可证状态保持 active（激活/心跳按 expires_at 拒绝），事件用于报表与通知。
	if n, err := st.Q().MarkExpiredLicenseEvents(ctx); err != nil {
		slog.Warn("mark expired failed", "err", err)
	} else if n > 0 {
		slog.Info("marked expired licenses", "count", n)
	}
}
