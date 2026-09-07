// Package store 封装 PostgreSQL 访问：连接池、迁移执行器与各仓储。
package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	Pool *pgxpool.Pool
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	// 每副本连接数可调：部署多副本时须按 PG max_connections 预算
	// （副本数 × MaxConns + 运维连接 ≤ max_connections）
	if v := os.Getenv("VFT_DB_MAX_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			cfg.MaxConns = int32(n)
		}
	}
	cfg.MinConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() { s.Pool.Close() }

// Migrate 依序执行 migrations 目录下的 .sql 文件（按文件名排序，幂等）。
func Migrate(ctx context.Context, databaseURL, dir string) error {
	if err := ensureSchemaMigrations(ctx, databaseURL); err != nil {
		return err
	}
	// PostgreSQL advisory lock prevents concurrent API replicas or migration Jobs from applying DDL together.
	lockConn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("store: connect for migration lock: %w", err)
	}
	defer lockConn.Close(ctx)
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended('vertify:migrations', 0))`); err != nil {
		return err
	}
	defer func() {
		_, _ = lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended('vertify:migrations', 0))`)
	}()
	entries, err := fs.ReadDir(os.DirFS(dir), ".")
	if err != nil {
		return fmt.Errorf("store: read migrations dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("store: connect for migrate: %w", err)
	}
	defer conn.Close(ctx)

	for _, f := range files {
		var done bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)", f).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sqlBytes, err := os.ReadFile(dir + string(os.PathSeparator) + f)
		if err != nil {
			return fmt.Errorf("store: read %s: %w", f, err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: apply %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(name, applied_at) VALUES ($1, now())", f); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func ensureSchemaMigrations(ctx context.Context, databaseURL string) error {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	return err
}

// IsUnique 判断是否唯一约束冲突。
func IsUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsInvalidInput 判断是否无效输入（如非 UUID 字符串传入 UUID 列）。
func IsInvalidInput(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "22P02"
}

// IsForeignKey 判断是否外键约束冲突（引用不存在的对象）。
func IsForeignKey(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// NotFound 统一包装 pgx.ErrNoRows。
func NotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoRows
	}
	return err
}

var ErrNoRows = errors.New("store: not found")
