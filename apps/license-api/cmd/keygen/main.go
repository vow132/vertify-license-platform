// keygen 生成开发/部署所需的全部密钥材料，输出可直接粘贴到 .env 的行。
// 输出仅在生成时展示一次；生产环境应使用 KMS/Vault 生成的密钥。
package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/vertify/license-platform/internal/crypto"
)

func main() {
	var signPairs []string
	for _, kid := range []string{"sign-a", "sign-b"} {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			die(err)
		}
		signPairs = append(signPairs, kid+":"+base64.RawURLEncoding.EncodeToString(seed))
	}
	fmt.Printf("VFT_SIGN_KEYS=%s\n", join(signPairs, ","))
	fmt.Printf("VFT_SIGN_ACTIVE_KID=sign-a\n")

	var kexPairs []string
	for _, kid := range []string{"kex-a", "kex-b"} {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			die(err)
		}
		mark := ""
		if kid == "kex-a" {
			mark = "*"
		}
		kexPairs = append(kexPairs, kid+":"+base64.RawURLEncoding.EncodeToString(priv.Bytes())+mark)
	}
	fmt.Printf("VFT_KEX_KEYS=%s\n", join(kexPairs, ","))

	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		die(err)
	}
	fmt.Printf("VFT_CARD_HMAC_KEY=%s\n", base64.RawURLEncoding.EncodeToString(hmacKey))

	// 示例初始管理员口令（仅开发；生产用强口令并立即轮换）
	fmt.Printf("VFT_INITIAL_ADMIN_USER=admin\n")
	pw, err := crypto.RandomToken(18)
	if err != nil {
		die(err)
	}
	fmt.Printf("VFT_INITIAL_ADMIN_PASSWORD=%s\n", pw)
}

func join(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "keygen:", err)
	os.Exit(1)
}
