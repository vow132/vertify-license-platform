// Package crypto 实现许可系统所需的标准密码学构件。
// 仅使用经过审计的标准算法：Ed25519、X25519、HKDF-SHA256、AES-256-GCM、
// ChaCha20-Poly1305、HMAC-SHA-256、Argon2id、RFC 6238 TOTP。不自造加密算法。
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Signer 是服务端签名私钥的抽象。生产环境实现必须由 KMS/HSM/Vault 承载，
// 私钥绝不进入源码、镜像、数据库或客户端。LocalSigner 仅用于开发/测试环境。
type Signer interface {
	// Sign 对消息签名，返回签名值与密钥 ID（kid）。
	Sign(msg []byte) (sig []byte, kid string, err error)
	// PublicKey 返回指定 kid 的公钥。
	PublicKey(kid string) (ed25519.PublicKey, bool)
	// ActiveKID 返回当前用于签名的 kid。
	ActiveKID() string
	// AllKIDs 返回全部可信公钥的 kid（含轮换中的旧密钥）。
	AllKIDs() []string
}

// LocalSigner 基于内存中的 Ed25519 私钥实现 Signer。
// 私钥来源应为受控 Secret（环境变量/密钥文件挂载），仓库中不得出现任何真实私钥。
type LocalSigner struct {
	mu      sync.RWMutex
	keys    map[string]ed25519.PrivateKey
	pubkeys map[string]ed25519.PublicKey
	active  string
}

// NewLocalSigner 用 seed（Ed25519 私钥种子的 base64url 编码）构建签名器。
// keys 的键为 kid，activeKID 必须是其中之一。
func NewLocalSigner(keys map[string]string, activeKID string) (*LocalSigner, error) {
	if len(keys) == 0 {
		return nil, errors.New("crypto: at least one signing key required")
	}
	if _, ok := keys[activeKID]; !ok {
		return nil, fmt.Errorf("crypto: active kid %q not in key set", activeKID)
	}
	s := &LocalSigner{
		keys:    make(map[string]ed25519.PrivateKey, len(keys)),
		pubkeys: make(map[string]ed25519.PublicKey, len(keys)),
		active:  activeKID,
	}
	for kid, seedB64 := range keys {
		if err := validateKID(kid); err != nil {
			return nil, err
		}
		seed, err := base64.RawURLEncoding.DecodeString(seedB64)
		if err != nil {
			return nil, fmt.Errorf("crypto: kid %s seed decode: %w", kid, err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("crypto: kid %s seed must be %d bytes, got %d", kid, ed25519.SeedSize, len(seed))
		}
		priv := ed25519.NewKeyFromSeed(seed)
		s.keys[kid] = priv
		s.pubkeys[kid] = priv.Public().(ed25519.PublicKey)
	}
	return s, nil
}

func validateKID(kid string) error {
	if kid == "" || len(kid) > 32 {
		return fmt.Errorf("crypto: invalid kid %q", kid)
	}
	for _, c := range kid {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("crypto: kid %q must be [a-z0-9-]", kid)
		}
	}
	return nil
}

func (s *LocalSigner) Sign(msg []byte) ([]byte, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	priv, ok := s.keys[s.active]
	if !ok {
		return nil, "", errors.New("crypto: active key missing")
	}
	sig := ed25519.Sign(priv, msg)
	return sig, s.active, nil
}

func (s *LocalSigner) PublicKey(kid string) (ed25519.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pk, ok := s.pubkeys[kid]
	return pk, ok
}

func (s *LocalSigner) ActiveKID() string { return s.active }

func (s *LocalSigner) AllKIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kids := make([]string, 0, len(s.pubkeys))
	for kid := range s.pubkeys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	return kids
}

// GenerateSeed 返回一个新的 Ed25519 私钥种子（base64url）。
// 用于运维生成新签名密钥；输出仅在生成时展示一次。
func GenerateSeed() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("crypto: generate seed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(seed), nil
}

// PublicKeysSnapshot 返回 kid -> base64url 公钥 的快照，供 /bootstrap 下发。
func PublicKeysSnapshot(s Signer) map[string]string {
	out := make(map[string]string)
	for _, kid := range s.AllKIDs() {
		if pk, ok := s.PublicKey(kid); ok {
			out[kid] = base64.RawURLEncoding.EncodeToString(pk)
		}
	}
	return out
}

// JoinKIDs 将 kid 列表拼接为稳定的展示字符串。
func JoinKIDs(kids []string) string { return strings.Join(kids, ",") }
