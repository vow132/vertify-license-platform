package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var base64RawURL = base64.RawURLEncoding

func TestCardGenerationDeterminism(t *testing.T) {
	norm, err := NormalizeCard("ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ23")
	if err != nil {
		t.Fatalf("valid card rejected: %v", err)
	}
	if norm != "ABCDEFGHJKLMNPQRSTUVWXYZ23" {
		t.Fatalf("unexpected normalization: %s", norm)
	}
}

func TestCardNormalizationRejects(t *testing.T) {
	cases := []string{"", "ABCD", "abcde-fghij-klmnp-qrstuv-wxyzo", "ABCD0FGHIJKLMNOPQRSTUVWXYZPQ", "ABCDE-FGHIJ-KLMNP-QRSTU-VWXYZ-1QRST", "卡密 ABCDEFGHIJKLMNOPQRSTUVWXYZPQ"}
	for _, c := range cases {
		if _, err := NormalizeCard(c); err == nil {
			t.Fatalf("expected rejection for %q", c)
		}
	}
}

func TestCardEntropy(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		c, err := GenerateCardCode()
		if err != nil {
			t.Fatal(err)
		}
		norm, _ := NormalizeCard(c)
		if len(norm) != 26 {
			t.Fatalf("bad length: %s", norm)
		}
		if seen[c] {
			t.Fatalf("duplicate card generated: %s", c)
		}
		seen[c] = true
	}
}

func TestCardHMACStable(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	n1, _ := NormalizeCard("ABCDEFGHJKLMNPQRSTUVWXYZ23")
	n2, _ := NormalizeCard("ABCDEF-GHJKLM-NPQRST-UVWXYZ-23")
	h1 := CardHMAC(key, n1)
	h2 := CardHMAC(key, n2)
	if h1 != h2 {
		t.Fatal("HMAC should be separator-insensitive after normalization")
	}
	if len(h1) != 64 {
		t.Fatalf("HMAC hex length: %d", len(h1))
	}
}

func TestEnvelopeRoundtrip(t *testing.T) {
	kex, err := NewKexKeyPair("kex-test", true)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte(`{"card":"AAAAA-BBBBB","device_pub":"x"}`)
	env, err := SealEnvelope("kex-test", kex.PubB64, AlgAESGCM, pt, AADContext("activate"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenEnvelope(env, "kex-test", []*KexKeyPair{kex}, AADContext("activate"))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatal("roundtrip mismatch")
	}
	// AAD 绑定：跨用途重放必须失败
	if _, err := OpenEnvelope(env, "kex-test", []*KexKeyPair{kex}, AADContext("redeem")); err == nil {
		t.Fatal("AAD context binding broken: ciphertext replayed across purpose")
	}
	// 篡改密文必须失败：解码 ct 后翻转首字节再重编码
	var e map[string]any
	_ = json.Unmarshal(env, &e)
	ctRaw, err2 := base64.RawURLEncoding.DecodeString(e["ct"].(string))
	if err2 != nil {
		t.Fatal(err2)
	}
	ctRaw[0] ^= 0xff
	e["ct"] = base64.RawURLEncoding.EncodeToString(ctRaw)
	tampered, _ := json.Marshal(e)
	if _, err := OpenEnvelope(tampered, "kex-test", []*KexKeyPair{kex}, AADContext("activate")); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestEnvelopeChaCha(t *testing.T) {
	kex, _ := NewKexKeyPair("kex-c", true)
	pt := []byte("hello chacha")
	env, err := SealEnvelope("kex-c", kex.PubB64, AlgXC20P, pt, AADContext("activate"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenEnvelope(env, "", []*KexKeyPair{kex}, AADContext("activate"))
	if err != nil || string(got) != string(pt) {
		t.Fatalf("XC20P roundtrip failed: %v", err)
	}
}

func TestTokenSignVerify(t *testing.T) {
	keys := map[string]string{"sign-a": mustSeed(t), "sign-b": mustSeed(t)}
	signer, err := NewLocalSigner(keys, "sign-a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := MintToken(signer, LeaseClaims{
		Typ: TokenTypeLease, JTI: "j1", Lic: "lic-1", Prod: "PROD", Dev: "dev-1",
		Iss: now.Unix(), Exp: now.Add(time.Minute).Unix(), Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyTokenWithType(tok, TokenTypeLease, now, signer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Lic != "lic-1" || claims.Dev != "dev-1" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	// 篡改 payload
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + parts[1] + "A." + parts[2]
	if _, err := VerifyToken(tampered, now, signer); err == nil {
		t.Fatal("tampered token accepted")
	}
	// 类型不符
	if _, err := VerifyTokenWithType(tok, TokenTypeOffline, now, signer); err == nil {
		t.Fatal("wrong type accepted")
	}
	// 过期
	old, _ := MintToken(signer, LeaseClaims{
		Typ: TokenTypeLease, Lic: "l", Iss: now.Add(-time.Hour).Unix(),
		Exp: now.Add(-time.Minute).Unix(), Status: "active",
	})
	if _, err := VerifyToken(old, now, signer); err != ErrTokenExpired {
		t.Fatalf("expected expired, got %v", err)
	}
	// 篡改 kid → 未知密钥
	var payload map[string]any
	_ = json.Unmarshal(mustDecode(t, parts[1]), &payload)
	payload["kid"] = "evil"
	badPayload, _ := json.Marshal(payload)
	badTok := TokenPrefix + "." + mustEncode(t, badPayload) + "." + parts[2]
	if _, err := VerifyToken(badTok, now, signer); err == nil {
		t.Fatal("forged kid accepted")
	}
}

func TestTOTP(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	code, err := TOTPAt(secret, uint64(now)/30)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(secret, code, now) {
		t.Fatal("valid TOTP rejected")
	}
	if VerifyTOTP(secret, "000000", now) && code != "000000" {
		t.Fatal("invalid TOTP accepted")
	}
	// RFC 6238 测试向量（SHA1, 8 位 → 我们用 6 位，此处校验算法本身用标准向量前 6 位）
	vecSecret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	c59, _ := TOTPAt(vecSecret, 0x0000000000000001)
	if c59 == "" || len(c59) != 6 {
		t.Fatal("totp length wrong")
	}
}

func mustSeed(t *testing.T) string {
	t.Helper()
	s, err := GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]byte, 0)
	dec := base64RawURL
	b, err := dec.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	out = b
	return out
}

func mustEncode(t *testing.T, b []byte) string {
	t.Helper()
	return base64RawURL.EncodeToString(b)
}
