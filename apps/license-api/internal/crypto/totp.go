package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
)

// RFC 6238 TOTP（SHA-1，6 位，30s 步长）—— 与主流验证器 App（Google Authenticator
// 等）兼容的唯一组合。这是封装 RFC 标准算法，不是自造加密。
const (
	totpStep   = 30
	totpDigits = 6
	totpSkew   = 1 // 允许 ±1 步（±30s）漂移
)

var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// NormalizeTOTPSecret 将用户录入的 base32 密钥规范化（大写、去空格与填充）。
func NormalizeTOTPSecret(s string) (string, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", ""))
	if len(s) < 16 || len(s) > 128 {
		return "", fmt.Errorf("totp: secret length %d out of range", len(s))
	}
	if _, err := b32NoPad.DecodeString(s); err != nil {
		return "", fmt.Errorf("totp: not valid base32: %w", err)
	}
	return s, nil
}

// TOTPAt 计算指定步的 TOTP 值。
func TOTPAt(secretB32 string, counter uint64) (string, error) {
	key, err := b32NoPad.DecodeString(secretB32)
	if err != nil {
		return "", fmt.Errorf("totp: decode secret: %w", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	code := bin % 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// VerifyTOTP 校验当前时间附近的 TOTP。恒定时间比较。
func VerifyTOTP(secretB32 string, code string, now int64) bool {
	if len(code) != totpDigits {
		return false
	}
	counter := uint64(now) / totpStep
	for d := -int64(totpSkew); d <= totpSkew; d++ {
		want, err := TOTPAt(secretB32, uint64(int64(counter)+d))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// TOTPProvisioningURI 生成验证器 App 扫码用 otpauth:// URI。
func TOTPProvisioningURI(secretB32, account, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, account, secretB32, issuer, totpDigits, totpStep)
}

// GenerateTOTPSecret 生成新密钥（base32，20 字节 = 160 bit）。
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32NoPad.EncodeToString(raw), nil
}
