package service

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/vertify/license-platform/internal/crypto"
)

// DeviceSignature 解析后的设备 Proof-of-Possession 签名头。
//
// 请求头 X-Vft-Device-Auth:
//
//	v1 pub=<b64url 32B 设备公钥> ts=<unix秒> nonce=<b64url 16B> seq=<单调递增> sig=<b64url>
//
// 签名覆盖串（crypto.DeviceAuthMessage）：
//
//	v1|<METHOD>|<path>|<ts>|<nonce>|<seq>|<sha256(body)>
//
// 激活时 pub 来自信封内载荷并要求一致；其余请求 pub 即身份（服务端查库取信任锚）。
type DeviceSignature struct {
	Pub   string
	TS    int64
	Nonce string
	Seq   int64
	Sig   []byte
}

var ErrDeviceAuthHeader = errors.New("device auth: malformed header")

// ParseDeviceSignature 解析请求头。header 形如 "v1 pub=.. ts=.. nonce=.. seq=.. sig=.."。
func ParseDeviceSignature(header string) (*DeviceSignature, error) {
	parts := strings.Fields(strings.TrimSpace(header))
	if len(parts) == 0 || parts[0] != "v1" {
		return nil, ErrDeviceAuthHeader
	}
	ds := &DeviceSignature{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, ErrDeviceAuthHeader
		}
		switch k {
		case "pub":
			ds.Pub = v
		case "ts":
			ts, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, ErrDeviceAuthHeader
			}
			ds.TS = ts
		case "nonce":
			ds.Nonce = v
		case "seq":
			seq, err := strconv.ParseInt(v, 10, 64)
			if err != nil || seq < 0 {
				return nil, ErrDeviceAuthHeader
			}
			ds.Seq = seq
		case "sig":
			sig, err := base64.RawURLEncoding.DecodeString(v)
			// Ed25519 为 64 字节定长；ECDSA P-256 为 DER 编码（典型 70-72 字节）
			if err != nil || len(sig) < 8 {
				return nil, ErrDeviceAuthHeader
			}
			ds.Sig = sig
		default:
			return nil, ErrDeviceAuthHeader
		}
	}
	if ds.Pub == "" || ds.TS == 0 || ds.Nonce == "" || len(ds.Sig) == 0 {
		return nil, ErrDeviceAuthHeader
	}
	return ds, nil
}

// Message 构造待签名消息（body 为原始请求体字节）。
func (d *DeviceSignature) Message(method, path string, body []byte) []byte {
	return crypto.DeviceAuthMessage(method, path, d.TS, d.Nonce, d.Seq, body)
}

// VerifyPub 按公钥类型分派验证：
//   - ed25519：对原始消息直接验签
//   - p256：ECDSA-P256/SHA-256 ASN.1 签名（TPM/BCrypt 产生的签名格式）
func (d *DeviceSignature) VerifyPub(pubB64, kty string, msg []byte) bool {
	raw, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil {
		return false
	}
	switch kty {
	case "p256":
		if len(raw) != 65 || raw[0] != 0x04 {
			return false
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), raw)
		if x == nil || y == nil {
			return false
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		digest := sha256.Sum256(msg)
		if len(d.Sig) == 64 {
			// Windows CNG（BCryptSignHash dwFlags=0）输出裸 r||s 定长格式
			r := new(big.Int).SetBytes(d.Sig[:32])
			s := new(big.Int).SetBytes(d.Sig[32:])
			return ecdsa.Verify(pub, digest[:], r, s)
		}
		// DER 编码（NCrypt/其它提供程序）
		return ecdsa.VerifyASN1(pub, digest[:], d.Sig)
	default:
		if len(raw) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(raw), msg, d.Sig)
	}
}

// Header 重建头字符串（测试与调试工具用）。
func (d *DeviceSignature) Header() string {
	return fmt.Sprintf("v1 pub=%s ts=%d nonce=%s seq=%d sig=%s",
		d.Pub, d.TS, d.Nonce, d.Seq, base64.RawURLEncoding.EncodeToString(d.Sig))
}
