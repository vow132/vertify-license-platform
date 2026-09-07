package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf" //nolint:staticcheck // Go 1.24+ 标准库
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// 激活/兑换请求的应用层信封加密。
// TLS 是传输层的必要基础，但卡密等机密在应用层再进行一次端到端加密：
// 客户端用服务端轮换的静态 X25519 公钥 + 自有临时密钥做 ECDH，
// HKDF-SHA256 派生密钥后用 AEAD 加密载荷。抓包者与 TLS 终止点均看不到明文卡密。
//
// 线上格式（JSON）：
//
//	{
//	  "kid": "kex-2026a",      // 服务端 KEX 密钥版本
//	  "alg": "A256GCM",        // 或 "XC20P"
//	  "epk": "<b64url 32B>",   // 客户端临时 X25519 公钥
//	  "nonce": "<b64url 12B>",
//	  "ct":   "<b64url>"       // AES/ChaCha20 密文 + AEAD tag
//	}
//
// KDF: HKDF-SHA256(shared, salt=epk_raw||server_pub_raw, info="vertify-envelope-v1")
// AAD: "vertify-envelope-v1|" + kid + "|" + alg

const (
	EnvelopeInfo = "vertify-envelope-v1"
	AlgAESGCM    = "A256GCM"
	AlgXC20P     = "XC20P"
)

var (
	ErrEnvelopeFormat   = errors.New("envelope: malformed payload")
	ErrEnvelopeKID      = errors.New("envelope: unknown key id")
	ErrEnvelopeAlg      = errors.New("envelope: unsupported algorithm")
	ErrEnvelopeDecrypt  = errors.New("envelope: authentication failed")
	ErrEnvelopeBadPoint = errors.New("envelope: invalid ephemeral key")
)

// KexKeyPair 是服务端信封加密 X25519 密钥对。私钥应存于 KMS/Secret；
// 轮换时新增 kid 并保留旧 kid 一段兼容窗口，仅解密不加密。
type KexKeyPair struct {
	KID     string
	Alg     string // 该密钥首选算法（A256GCM）
	PrivKey *ecdh.PrivateKey
	PubB64  string // base64url(raw 32B)
	Active  bool
}

type Envelope struct {
	KID   string `json:"kid"`
	Alg   string `json:"alg"`
	EPK   string `json:"epk"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// NewKexKeyPair 生成新的服务端 KEX 密钥对（开发/测试用；生产应由 KMS 生成并导入）。
func NewKexKeyPair(kid string, active bool) (*KexKeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("envelope: generate key: %w", err)
	}
	pub := priv.PublicKey().Bytes()
	return &KexKeyPair{
		KID:     kid,
		Alg:     AlgAESGCM,
		PrivKey: priv,
		PubB64:  base64.RawURLEncoding.EncodeToString(pub),
		Active:  active,
	}, nil
}

// NewKexKeyPairFromSeed 用固定 32 字节种子构建（测试向量用）。
func NewKexKeyPairFromSeed(kid string, seed []byte) (*KexKeyPair, error) {
	if len(seed) != 32 {
		return nil, errors.New("envelope: seed must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("envelope: bad seed: %w", err)
	}
	return &KexKeyPair{
		KID:     kid,
		Alg:     AlgAESGCM,
		PrivKey: priv,
		PubB64:  base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		Active:  false,
	}, nil
}

// SealEnvelope 客户端侧封装（Go 测试与 SDK 一致性向量生成用）。
// kid 为服务端 KEX 密钥 ID（来自 /v1/bootstrap），参与 AAD 绑定。
func SealEnvelope(kid, serverPubB64 string, alg string, plaintext, aadContext []byte) ([]byte, error) {
	serverPubRaw, err := base64.RawURLEncoding.DecodeString(serverPubB64)
	if err != nil || len(serverPubRaw) != 32 {
		return nil, ErrEnvelopeFormat
	}
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubRaw)
	if err != nil {
		return nil, ErrEnvelopeBadPoint
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return sealEnvelopeWithEphemeral(kid, eph, serverPub, alg, plaintext, aadContext)
}

// sealEnvelopeWithEphemeral 供测试向量复现。
func sealEnvelopeWithEphemeral(kid string, eph *ecdh.PrivateKey, serverPub *ecdh.PublicKey, alg string, plaintext, aadContext []byte) ([]byte, error) {
	if alg != AlgAESGCM && alg != AlgXC20P {
		return nil, ErrEnvelopeAlg
	}
	shared, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, ErrEnvelopeBadPoint
	}
	epkRaw := eph.PublicKey().Bytes()
	spkRaw := serverPub.Bytes()
	key, err := deriveEnvelopeKey(shared, epkRaw, spkRaw)
	if err != nil {
		return nil, err
	}
	var aead cipher.AEAD
	if alg == AlgAESGCM {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	} else {
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := envelopeAAD(kid, alg, aadContext)
	ct := aead.Seal(nil, nonce, plaintext, aad)
	env := Envelope{
		KID:   kid,
		Alg:   alg,
		EPK:   base64.RawURLEncoding.EncodeToString(epkRaw),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		CT:    base64.RawURLEncoding.EncodeToString(ct),
	}
	return json.Marshal(env)
}

// deriveEnvelopeKey: HKDF-SHA256(shared, salt=epk||serverPub, info=EnvelopeInfo) -> 32B
func deriveEnvelopeKey(shared, epkRaw, spkRaw []byte) ([]byte, error) {
	salt := make([]byte, 0, len(epkRaw)+len(spkRaw))
	salt = append(salt, epkRaw...)
	salt = append(salt, spkRaw...)
	return hkdf.Key(sha256.New, shared, salt, EnvelopeInfo, 32)
}

func envelopeAAD(kid, alg string, aadContext []byte) []byte {
	out := make([]byte, 0, len(EnvelopeInfo)+len(kid)+len(alg)+len(aadContext)+2)
	out = append(out, []byte(EnvelopeInfo)...)
	out = append(out, '|')
	out = append(out, []byte(kid)...)
	out = append(out, '|')
	out = append(out, []byte(alg)...)
	if len(aadContext) > 0 {
		out = append(out, '|')
		out = append(out, aadContext...)
	}
	return out
}

// OpenEnvelope 服务端解封装。kid 为空时尝试全部已知密钥（仅允许用于兼容窗口内的旧客户端）。
func OpenEnvelope(envelopeJSON []byte, kid string, keys []*KexKeyPair, aadContext []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, ErrEnvelopeFormat
	}
	if env.Alg != AlgAESGCM && env.Alg != AlgXC20P {
		return nil, ErrEnvelopeAlg
	}
	candidates := keys
	if kid != "" || env.KID != "" {
		want := env.KID
		if kid != "" {
			want = kid
		}
		candidates = nil
		for _, k := range keys {
			if k.KID == want {
				candidates = append(candidates, k)
			}
		}
		if len(candidates) == 0 {
			return nil, ErrEnvelopeKID
		}
	}
	epkRaw, err := base64.RawURLEncoding.DecodeString(env.EPK)
	if err != nil || len(epkRaw) != 32 {
		return nil, ErrEnvelopeFormat
	}
	nonce, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, ErrEnvelopeFormat
	}
	ct, err := base64.RawURLEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, ErrEnvelopeFormat
	}
	epkPub, err := ecdh.X25519().NewPublicKey(epkRaw)
	if err != nil {
		return nil, ErrEnvelopeBadPoint
	}
	var lastErr error = ErrEnvelopeDecrypt
	for _, k := range candidates {
		shared, err := k.PrivKey.ECDH(epkPub)
		if err != nil {
			continue
		}
		key, err := deriveEnvelopeKey(shared, epkRaw, k.PrivKey.PublicKey().Bytes())
		if err != nil {
			continue
		}
		var aead cipher.AEAD
		if env.Alg == AlgAESGCM {
			block, err := aes.NewCipher(key)
			if err != nil {
				continue
			}
			aead, err = cipher.NewGCM(block)
			if err != nil {
				continue
			}
		} else {
			aead, err = chacha20poly1305.New(key)
			if err != nil {
				continue
			}
		}
		if len(nonce) != aead.NonceSize() {
			lastErr = ErrEnvelopeFormat
			continue
		}
		pt, err := aead.Open(nil, nonce, ct, envelopeAAD(k.KID, env.Alg, aadContext))
		if err != nil {
			lastErr = ErrEnvelopeDecrypt
			continue
		}
		return pt, nil
	}
	return nil, lastErr
}

// AADContext 返回标准 AAD 上下文（区分激活与兑换，防跨接口重放密文）。
func AADContext(purpose string) []byte {
	return []byte("purpose=" + purpose)
}
