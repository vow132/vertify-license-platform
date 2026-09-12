// 一次性开发工具：为本地开发库生成一个临时预览管理员（用后即删，不进仓库）。
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/vertify/license-platform/internal/argon2id"
	"github.com/vertify/license-platform/internal/store"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: previewadmin <password>")
		os.Exit(1)
	}
	hash, err := argon2id.Hash(os.Args[1], argon2id.DefaultParams())
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	dbURL := os.Getenv("VFT_DATABASE_URL")
	if dbURL == "" {
		panic("VFT_DATABASE_URL required")
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		panic(err)
	}
	defer st.Close()
	_, err = st.Pool.Exec(ctx, `INSERT INTO admins (username, password_hash, display_name, role, mfa_enabled, must_change_password, status)
		VALUES ('preview_tmp', $1, '界面预览', 'superadmin', false, false, 'active')
		ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`, hash)
	if err != nil {
		panic(err)
	}
	fmt.Println("preview admin ready")
}
