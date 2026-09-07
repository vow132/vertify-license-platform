package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SigToken：服务端签名的短生命周期凭据（授权租约 / 设备访问令牌 / 离线许可）。
//
// 线上格式（仿 COSE Sign1 的最小实现，便于 C++ 端零依赖验签）：
//
//	VLT1.<b64url(payloadJSON)>.<b64url(Ed25519sig)>
//
// 签名覆盖的字节 = 第二段 b64url(payload) 的原始 ASCII 字节（原样传输、原样验证），
// 客户端无需重建规范化 JSON，杜绝序列化歧义。
// C++ SDK 内嵌公钥集合（可轮换），仅验签、绝不嵌入私钥。

const (
	TokenTypeLease    = "lease"   // 在线授权租约（心跳续发）
	TokenTypeAccess   = "access"  // 设备访问令牌（调用受限接口）
	TokenTypeOffline  = "offline" // 离线许可
	TokenPrefix       = "VLT1"
	TokenKDFLabelSize = 32
)

var (
	ErrTokenFormat      = errors.New("token: malformed")
	ErrTokenBadSig      = errors.New("token: signature verification failed")
	ErrTokenUnknownKID  = errors.New("token: unknown key id")
	ErrTokenExpired     = errors.New("token: expired")
	ErrTokenNotYetValid = errors.New("token: not yet valid")
	ErrTokenType        = errors.New("token: wrong type")
)

// LeaseClaims 是在线授权租约载荷。字段名刻意短小（减小 C++ 端解析面）。
type LeaseClaims struct {
	Typ    string   `json:"typ"`             // lease | access | offline
	KID    string   `json:"kid"`             // 签名密钥 ID
	JTI    string   `json:"jti"`             // 租约唯一 ID（防跨设备复制后的关联分析）
	Lic    string   `json:"lic"`             // license ID
	Prod   string   `json:"prod"`            // 产品代码
	Dev    string   `json:"dev,omitempty"`   // 绑定设备 ID（离线/租约必填）
	Feat   []string `json:"feat,omitempty"`  // 授权功能列表
	Iss    int64    `json:"iat"`             // 签发时间（服务端时间）
	Exp    int64    `json:"exp"`             // 过期时间
	LicExp int64    `json:"lex,omitempty"`   // 许可证到期时间（0 = 永久）
	Pol    int64    `json:"pol"`             // 策略版本
	HBI    int      `json:"hbi,omitempty"`   // 心跳间隔（秒）
	Grace  int      `json:"grace,omitempty"` // 离线宽限（秒）
	Status string   `json:"st"`              // active | frozen | revoked ...
	MinVer string   `json:"mver,omitempty"`  // 最低客户端版本
	Nonce  string   `json:"nnc,omitempty"`   // 签发随机数（离线许可防重放）
}

// MintToken 用 Signer 签发令牌。payload 由 encoding/json 序列化（map 键序稳定，
// 但客户端验签不依赖键序：直接对传输段验签）。
func MintToken(s Signer, claims LeaseClaims) (string, error) {
	claims.KID = s.ActiveKID()
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("token: marshal: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig, kid, err := s.Sign([]byte(payloadB64))
	if err != nil {
		return "", fmt.Errorf("token: sign: %w", err)
	}
	// kid 必须与 Signer 实际使用的 kid 一致
	if kid != claims.KID {
		return "", errors.New("token: kid mismatch")
	}
	return TokenPrefix + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyToken 验证令牌签名与时间窗，返回载荷。
// now 提供方为调用方（服务端一律使用可信时间）。
func VerifyToken(token string, now time.Time, keys Signer) (LeaseClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != TokenPrefix {
		return LeaseClaims{}, ErrTokenFormat
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return LeaseClaims{}, ErrTokenFormat
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return LeaseClaims{}, ErrTokenFormat
	}
	var claims LeaseClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return LeaseClaims{}, ErrTokenFormat
	}
	pk, ok := keys.PublicKey(claims.KID)
	if !ok {
		return LeaseClaims{}, ErrTokenUnknownKID
	}
	// 关键：对传输中的第二段原始字节验签
	if !ed25519.Verify(pk, []byte(parts[1]), sig) {
		return LeaseClaims{}, ErrTokenBadSig
	}
	if now.Unix() > claims.Exp {
		return LeaseClaims{}, ErrTokenExpired
	}
	if claims.Iss > now.Unix()+60 { // 允许 60s 时钟偏差
		return LeaseClaims{}, ErrTokenNotYetValid
	}
	return claims, nil
}

// VerifyTokenWithType = VerifyToken + 类型断言。
func VerifyTokenWithType(token string, typ string, now time.Time, keys Signer) (LeaseClaims, error) {
	c, err := VerifyToken(token, now, keys)
	if err != nil {
		return c, err
	}
	if c.Typ != typ {
		return c, ErrTokenType
	}
	return c, nil
}

// DeviceSignature 覆盖的规范串：
//
//	"v1|<method>|<path>|<ts>|<nonce>|<seq>|<sha256(body)>"
func DeviceAuthMessage(method, path string, ts int64, nonceB64 string, seq int64, body []byte) []byte {
	bodyHash := sha256.Sum256(body)
	var sb strings.Builder
	sb.WriteString("v1|")
	sb.WriteString(strings.ToUpper(method))
	sb.WriteByte('|')
	sb.WriteString(path)
	sb.WriteByte('|')
	sb.WriteString(fmt.Sprintf("%d", ts))
	sb.WriteByte('|')
	sb.WriteString(nonceB64)
	sb.WriteByte('|')
	sb.WriteString(fmt.Sprintf("%d", seq))
	sb.WriteByte('|')
	sb.Write(bodyHash[:])
	return []byte(sb.String())
}

// TokenTypeUser 终端用户会话令牌（账号制模式）。
const TokenTypeUser = "user"
