// 数据库迁移工具：依序执行 db/migrations/*.sql（幂等，schema_migrations 记录进度）。
//
// 用法：go run ./cmd/migrate up
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/vertify/license-platform/internal/store"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "up" {
		fmt.Fprintln(os.Stderr, "usage: migrate up")
		os.Exit(2)
	}
	url := os.Getenv("VFT_DATABASE_URL")
	if url == "" {
		url = "postgres://vertify:vertify@127.0.0.1:54329/vertify?sslmode=disable"
	}
	dir := os.Getenv("VFT_MIGRATIONS_DIR")
	if dir == "" {
		dir = findDir()
	}
	if err := store.Migrate(context.Background(), url, dir); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
	fmt.Println("migrations up to date")
}

func findDir() string {
	for _, c := range []string{"../../db/migrations", "../../../db/migrations", "db/migrations", "/db/migrations"} {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return "../../db/migrations"
}
