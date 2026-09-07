package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// 卡密设计与存储策略：
//   - 卡密由 CSPRNG 生成，26 个字符 × 5 bit ≈ 130 bit 熵（字母表 32 个无歧义字符）。
//   - 展示格式：XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X（5 组，末组 6 字符）。
//   - 数据库不保存完整明文：保存 lookup = HMAC-SHA256(hmacKey, normalized) 的 hex，
//     以及展示前缀（首组）用于客服检索。HMAC 密钥存于 KMS/Secret。
//   - 明文仅存在于生成与导出环节，导出需要高危权限并被完整审计。
var (
	ErrCardFormat = errors.New("card: invalid format")
	ErrCardRandom = errors.New("card: rng failure")
)

// CardAlphabet excludes易混淆字符 I、O、0、1。
const CardAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

const (
	cardRandomLen  = 26 // 130 bits 熵
	cardGroupFirst = 5  // 4 组 5 字符 + 1 组 6 字符
	cardGroups     = 5
)

// GenerateCardCode 生成新卡密（展示格式，含分隔符）。
func GenerateCardCode() (string, error) {
	buf := make([]byte, cardRandomLen)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(CardAlphabet))))
		if err != nil {
			return "", ErrCardRandom
		}
		buf[i] = CardAlphabet[n.Int64()]
	}
	var sb strings.Builder
	group := 0
	for i, c := range buf {
		if i > 0 && i%cardGroupFirst == 0 && group < cardGroups-1 {
			sb.WriteByte('-')
			group++
		}
		sb.WriteByte(c)
	}
	return sb.String(), nil
}

func ValidateCardPrefix(prefix string) (string, error) {
	prefix = strings.ToUpper(strings.TrimSpace(prefix))
	if len(prefix) > 8 {
		return "", ErrCardFormat
	}
	for _, r := range prefix {
		if !strings.ContainsRune(CardAlphabet, r) {
			return "", ErrCardFormat
		}
	}
	if len(prefix) > cardRandomLen-16 {
		return "", ErrCardFormat
	}
	return prefix, nil
}

func GenerateCardCodeWithPrefix(prefix string) (string, error) {
	prefix, err := ValidateCardPrefix(prefix)
	if err != nil {
		return "", err
	}
	buf := make([]byte, cardRandomLen-len(prefix))
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(CardAlphabet))))
		if err != nil {
			return "", ErrCardRandom
		}
		buf[i] = CardAlphabet[n.Int64()]
	}
	normalized := prefix + string(buf)
	var sb strings.Builder
	for i, c := range normalized {
		if i > 0 && i%cardGroupFirst == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(byte(c))
	}
	return sb.String(), nil
}
func GenerateCardBatchWithPrefix(n int, prefix string) ([]string, error) {
	if n <= 0 || n > 100_000 {
		return nil, fmt.Errorf("card: batch size %d out of range [1,100000]", n)
	}
	prefix, err := ValidateCardPrefix(prefix)
	if err != nil {
		return nil, err
	}
	cards := make([]string, 0, n)
	seen := make(map[string]struct{}, n)
	for len(cards) < n {
		c, err := GenerateCardCodeWithPrefix(prefix)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		cards = append(cards, c)
	}
	return cards, nil
}

// GenerateCardBatch 批量生成。要求数量上限以防误操作。
func GenerateCardBatch(n int) ([]string, error) {
	if n <= 0 || n > 100_000 {
		return nil, fmt.Errorf("card: batch size %d out of range [1,100000]", n)
	}
	cards := make([]string, 0, n)
	seen := make(map[string]struct{}, n)
	for len(cards) < n {
		c, err := GenerateCardCode()
		if err != nil {
			return nil, err
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		cards = append(cards, c)
	}
	return cards, nil
}

// NormalizeCard 将用户输入规范化为大写无分隔符形式。
// 规范化仅去除空白与连字符并转大写；出现字母表外字符时直接拒绝
// （不做 O→0 之类猜测映射，避免把错误输入“修正”成别人的卡密）。
func NormalizeCard(input string) (string, error) {
	var sb strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(input)) {
		switch {
		case r == '-' || r == ' ' || r == '_':
			continue
		default:
			if !strings.ContainsRune(CardAlphabet, r) {
				return "", ErrCardFormat
			}
			sb.WriteRune(r)
		}
	}
	out := sb.String()
	if len(out) != cardRandomLen {
		return "", ErrCardFormat
	}
	return out, nil
}

func FormatCard(normalized string) string {
	var sb strings.Builder
	for i, r := range normalized {
		if i > 0 && i%cardGroupFirst == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func CardHMAC(hmacKey []byte, normalized string) string {
	m := hmac.New(sha256.New, hmacKey)
	m.Write([]byte(normalized))
	return hex.EncodeToString(m.Sum(nil))
}

// CardPrefix 返回展示用前缀（首组 5 字符），用于列表检索与掩码显示。
func CardPrefix(normalized string) string {
	if len(normalized) < cardGroupFirst {
		return normalized
	}
	return normalized[:cardGroupFirst]
}

// MaskCard 将规范化卡密掩码为 AB123-****（仅显示首组与末 2 位）。
func MaskCard(normalized string) string {
	if len(normalized) < cardGroupFirst+2 {
		return "***"
	}
	return normalized[:cardGroupFirst] + "-****" + normalized[len(normalized)-2:]
}

// RandomToken 生成 n 字节 CSPRNG 随机数的 base64url 编码（无填充）。
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
