// Package argon2id 提供管理员口令哈希（RFC 9106 推荐、OWASP 参数）。
package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// 参数遵循 OWASP Password Storage Cheat Sheet 推荐底线：
// m=19456 (KiB), t=2, p=1。可按部署硬件上调。
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	KeyLen    uint32
	SaltLen   uint32
}

func DefaultParams() Params {
	return Params{MemoryKiB: 19456, Time: 2, Threads: 1, KeyLen: 32, SaltLen: 16}
}

var ErrMismatch = errors.New("argon2id: password mismatch")
var ErrFormat = errors.New("argon2id: malformed hash string")

// Hash 生成 PHC 格式哈希串：
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
func Hash(password string, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2id: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify 校验口令与 PHC 哈希。参数取自哈希串本身（支持后续上调参数平滑迁移）。
func Verify(password, phc string) (bool, error) {
	parts := strings.Split(phc, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrFormat
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrFormat
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, ErrFormat
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrFormat
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrFormat
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
