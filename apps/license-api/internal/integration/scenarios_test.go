//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/vertify/license-platform/internal/crypto"
)

type errResp struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func codeOf(body []byte) string {
	var e errResp
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

// comp 按 fp 生成互不相同的指纹分量摘要（模拟不同硬件）。
// 服务端要求每个分量为 64 位十六进制摘要（sha256），此处按同规则生成。
func comp(fp string) []string {
	h := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	return []string{
		h(fp + "-guid"),  // sha256(machineGUID)
		h(fp + "-board"), // sha256(baseboard serial)
		h(fp + "-disk"),  // sha256(system disk serial)
	}
}

// TestFullLifecycle 全业务闭环：制卡→激活→心跳→冻结→解绑→重绑→续费→吊销。
func TestFullLifecycle(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	if len(fx.Batch) < 4 || len(fx.RenewalCards) < 1 {
		t.Fatalf("fixture cards missing: %d / %d", len(fx.Batch), len(fx.RenewalCards))
	}

	// 1. 激活
	dev := newDevice(t, e)
	st, body := dev.activate(t, fx.Batch[0], "fp1", comp("fp1"))
	if st != 200 {
		t.Fatalf("activate: %d %s", st, body)
	}
	var act struct {
		LicenseID string   `json:"license_id"`
		DeviceID  string   `json:"device_id"`
		Lease     string   `json:"lease"`
		Features  []string `json:"features"`
	}
	if err := json.Unmarshal(body, &act); err != nil {
		t.Fatal(err)
	}
	dev.LicenseID, dev.DeviceID, dev.Lease = act.LicenseID, act.DeviceID, act.Lease
	if len(act.Features) == 0 {
		t.Fatal("features missing in activation response")
	}

	// 2. 租约验签与字段校验（C++ SDK 的验签行为）
	claims, err := crypto.VerifyTokenWithType(act.Lease, crypto.TokenTypeLease, time.Now(), e.keys)
	if err != nil {
		t.Fatalf("lease verify: %v", err)
	}
	if claims.Lic != act.LicenseID || claims.Dev != act.DeviceID {
		t.Fatalf("lease binding mismatch: %+v", claims)
	}
	if claims.Exp-time.Now().Unix() > 310 {
		t.Fatalf("lease TTL too long: %d", claims.Exp-time.Now().Unix())
	}

	// 3. 心跳正常
	st, body = dev.heartbeat(t)
	if st != 200 {
		t.Fatalf("heartbeat: %d %s", st, body)
	}
	var hb struct {
		Lease  string `json:"lease"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(body, &hb)
	if hb.Status != "active" {
		t.Fatalf("hb status: %s", hb.Status)
	}

	// 4. 同卡同机同密钥重激活（幂等，模拟客户端重启）
	st, body = dev.activate(t, fx.Batch[0], "fp1", comp("fp1"))
	if st != 200 {
		t.Fatalf("reactivation: %d %s", st, body)
	}

	// 5. 冻结 → 心跳被拒
	// 查卡片列表拿卡 ID
	st, body = e.admin.get(t, "/admin/v1/cards?limit=500")
	if st != 200 {
		t.Fatalf("list cards: %d %s", st, body)
	}
	var cards struct {
		Items []struct {
			ID     string `json:"id"`
			Prefix string `json:"prefix"`
			Status string `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &cards)
	prefix := strings.Split(fx.Batch[0], "-")[0]
	var cardID string
	for _, c := range cards.Items {
		if c.Prefix == prefix {
			cardID = c.ID
		}
	}
	if cardID == "" {
		t.Fatal("card not found in list")
	}
	st, body = e.admin.post(t, "/admin/v1/cards/"+cardID+"/action", map[string]any{
		"action": "freeze", "reason": "测试冻结",
	})
	if st != 200 {
		t.Fatalf("freeze: %d %s", st, body)
	}
	st, body = dev.heartbeat(t)
	if st != 403 || codeOf(body) != "LICENSE_FROZEN" {
		t.Fatalf("frozen heartbeat not rejected: %d %s", st, body)
	}

	// 6. 解冻 → 心跳恢复
	st, body = e.admin.post(t, "/admin/v1/cards/"+cardID+"/action", map[string]any{"action": "unfreeze"})
	if st != 200 {
		t.Fatalf("unfreeze: %d %s", st, body)
	}
	st, body = dev.heartbeat(t)
	if st != 200 {
		t.Fatalf("heartbeat after unfreeze: %d %s", st, body)
	}

	// 7. 设备名额与并发名额：
	//    device_limit=2（绑定门），concurrent_limit=1（并发门，在心跳强制）
	dev3 := newDevice(t, e)
	st, body = dev3.activate(t, fx.Batch[0], "fp2", comp("fp2"))
	if st != 200 {
		t.Fatalf("second device activate: %d %s", st, body)
	}
	// dev 仍持有唯一并发名额 → dev3 心跳应被并发限制拒绝
	st, body = dev3.heartbeat(t)
	if st != 409 || codeOf(body) != "CONCURRENT_LIMIT" {
		t.Fatalf("concurrent limit not enforced: %d %s", st, body)
	}
	// 第 3 台设备绑定必须被设备名额拒绝
	dev4 := newDevice(t, e)
	st, body = dev4.activate(t, fx.Batch[0], "fp3", comp("fp3"))
	if st != 409 || codeOf(body) != "DEVICE_LIMIT" {
		t.Fatalf("third device must hit DEVICE_LIMIT: %d %s", st, body)
	}

	// 8. dev 自助解绑 → 释放并发名额 → dev3 接管 → dev4 可绑定
	st, body = dev.deactivate(t)
	if st != 200 {
		t.Fatalf("deactivate: %d %s", st, body)
	}
	st, body = dev3.heartbeat(t)
	if st != 200 {
		t.Fatalf("dev3 heartbeat after release: %d %s", st, body)
	}
	st, body = dev4.activate(t, fx.Batch[0], "fp3", comp("fp3"))
	if st != 200 {
		t.Fatalf("rebind after unbind: %d %s", st, body)
	}

	// 9. 续费卡兑换（经当前在线设备 dev3）
	oldExp := int64(0)
	st, body = e.admin.get(t, "/admin/v1/licenses/"+act.LicenseID)
	if st == 200 {
		var detail struct {
			License struct {
				ExpiresAt *int64 `json:"expires_at"`
			} `json:"license"`
		}
		_ = json.Unmarshal(body, &detail)
		if detail.License.ExpiresAt != nil {
			oldExp = *detail.License.ExpiresAt
		}
	}
	st, body = dev3.redeem(t, fx.RenewalCards[0])
	if st != 200 {
		t.Fatalf("redeem: %d %s", st, body)
	}
	var redeem struct {
		NewExpiry *int64 `json:"new_expiry"`
		DaysAdded int    `json:"days_added"`
	}
	_ = json.Unmarshal(body, &redeem)
	if redeem.DaysAdded != 30 {
		t.Fatalf("days added: %d", redeem.DaysAdded)
	}
	if redeem.NewExpiry != nil && oldExp > 0 && *redeem.NewExpiry <= oldExp {
		t.Fatal("expiry not extended")
	}

	// 10. 吊销 → 心跳被拒（一个心跳周期内传播）
	st, body = e.admin.post(t, "/admin/v1/licenses/"+act.LicenseID+"/action", map[string]any{
		"action": "revoke", "reason": "测试吊销",
	})
	if st != 200 {
		t.Fatalf("revoke: %d %s", st, body)
	}
	st, body = dev3.heartbeat(t)
	if st != 403 || codeOf(body) != "LICENSE_REVOKED" {
		t.Fatalf("revoked heartbeat not rejected: %d %s", st, body)
	}

	// 11. 吊销后的卡不能再激活
	dev5 := newDevice(t, e)
	st, body = dev5.activate(t, fx.Batch[0], "fp9", comp("fp9"))
	if st != 403 || codeOf(body) != "CARD_REVOKED" {
		t.Fatalf("revoked card activation: %d %s", st, body)
	}
}

// TestSecurityNegatives 安全负向：防重放、防篡改、防伪造、防枚举、会话安全。
func TestSecurityNegatives(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	dev := newDevice(t, e)
	st, body := dev.activate(t, fx.Batch[1], "fpsec", comp("fpsec"))
	if st != 200 {
		t.Fatalf("activate: %d %s", st, body)
	}
	var act struct {
		LicenseID string `json:"license_id"`
		DeviceID  string `json:"device_id"`
	}
	_ = json.Unmarshal(body, &act)
	dev.LicenseID, dev.DeviceID = act.LicenseID, act.DeviceID

	// 1. 正常心跳记录 seq
	st, body = dev.heartbeat(t)
	if st != 200 {
		t.Fatalf("heartbeat1: %d %s", st, body)
	}

	// 2. 序列号倒退必须拒绝
	oldSeq := dev.seq - 1
	savedSeq := dev.seq
	dev.seq = oldSeq
	st, body = dev.heartbeat(t)
	if st != 409 || codeOf(body) != "SEQ_REGRESSION" {
		t.Fatalf("seq regression not caught: %d %s", st, body)
	}
	dev.seq = savedSeq
	st, body = dev.heartbeat(t)
	if st != 200 {
		t.Fatalf("heartbeat after restore: %d %s", st, body)
	}

	// 3. 重放：完全相同的请求（同 nonce/seq/时间戳/体）必须拒绝
	hbBody := mustJSON(map[string]any{"device_id": dev.DeviceID, "client_version": "1.0.0"})
	ts := time.Now().Unix()
	nonce := mustNonce(t)
	dev.seq++
	st, body = dev.heartbeatRaw(t, hbBody, ts, nonce, dev.seq)
	if st != 200 {
		t.Fatalf("fresh heartbeat: %d %s", st, body)
	}
	st, body = dev.heartbeatRaw(t, hbBody, ts, nonce, dev.seq)
	if st != 409 || codeOf(body) != "REPLAY_DETECTED" {
		t.Fatalf("replay not caught: %d %s", st, body)
	}

	// 4. 陈旧时间戳必须拒绝
	dev.seq++
	st, body = dev.heartbeatRaw(t, hbBody, time.Now().Add(-10*time.Minute).Unix(), mustNonce(t), dev.seq)
	if st != 409 || codeOf(body) != "REPLAY_DETECTED" {
		t.Fatalf("stale timestamp not caught: %d %s", st, body)
	}

	// 5. 篡改请求体（签名基于原体）必须拒绝
	tampered := mustJSON(map[string]any{"device_id": dev.DeviceID, "client_version": "9.9.9"})
	dev.seq++
	hdr := dev.deviceAuthHeader("POST", "/v1/heartbeat", hbBody, time.Now().Unix(), mustNonce(t), dev.seq)
	st, body = e.post("/v1/heartbeat", tampered, map[string]string{"X-Vft-Device-Auth": hdr})
	if st != 401 || codeOf(body) != "BAD_SIGNATURE" {
		t.Fatalf("tampered body not caught: %d %s", st, body)
	}

	// 6. 伪造设备（未注册公钥）必须拒绝
	rogue := newDevice(t, e)
	rogueBody := mustJSON(map[string]any{"device_id": dev.DeviceID, "client_version": "1.0.0"})
	rogueHdr := rogue.deviceAuthHeader("POST", "/v1/heartbeat", rogueBody, time.Now().Unix(), mustNonce(t), 1)
	st, body = e.post("/v1/heartbeat", rogueBody, map[string]string{"X-Vft-Device-Auth": rogueHdr})
	if st != 404 && st != 401 {
		t.Fatalf("rogue device accepted: %d %s", st, body)
	}

	// 7. 篡改租约任何字段后 SDK 验签必须失败
	st, body = dev.heartbeat(t)
	if st != 200 {
		t.Fatalf("heartbeat for lease: %d %s", st, body)
	}
	var hb struct {
		Lease string `json:"lease"`
	}
	_ = json.Unmarshal(body, &hb)
	parts := strings.Split(hb.Lease, ".")
	if len(parts) != 3 {
		t.Fatalf("lease format: %s", hb.Lease)
	}
	tamperedLease := parts[0] + "." + parts[1] + "x." + parts[2]
	if _, err := crypto.VerifyToken(tamperedLease, time.Now(), e.keys); err == nil {
		t.Fatal("tampered lease accepted by verifier")
	}
	// 用错误公钥验证必须失败
	rogueSigner, _ := crypto.NewLocalSigner(map[string]string{"evil": mustSeed(t)}, "evil")
	if _, err := crypto.VerifyToken(hb.Lease, time.Now(), rogueSigner); err == nil {
		t.Fatal("lease verified with wrong key")
	}

	// 8. 激活信封跨用途重放：activate 的密文发到 redeem 必须失败
	actEnv := dev.sealEnvelope(t, "activate", map[string]any{
		"card": fx.Batch[2], "components": comp("sec"), "device_pub": dev.pubB64,
		"trust_level": "tpm", "client_version": "1.0.0",
	})
	dev.seq++
	rhdr := dev.deviceAuthHeader("POST", "/v1/redeem", actEnv, time.Now().Unix(), mustNonce(t), dev.seq)
	st, body = e.post("/v1/redeem", actEnv, map[string]string{"X-Vft-Device-Auth": rhdr})
	if st == 200 {
		t.Fatal("activate envelope accepted by redeem endpoint")
	}

	// 9. 管理面 CSRF：无 CSRF 头的写请求必须拒绝
	st, body = e.post("/admin/v1/products", mustJSON(map[string]any{"code": "EVIL", "name": "x"}), nil)
	if st != 403 {
		t.Fatalf("missing CSRF not rejected: %d %s", st, body)
	}

	// 10. 未认证访问必须拒绝
	{
		anon, _ := cookiejar.New(nil)
		anonClient := &http.Client{Jar: anon}
		resp, err := anonClient.Get(e.ts.URL + "/admin/v1/audit")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("unauthenticated audit access: %d", resp.StatusCode)
		}
	}

	// 11. 激活响应与错误不得包含内部细节
	st, body = dev.activate(t, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZZ", "fpnone", comp("fpnone"))
	if st == 200 {
		t.Fatal("nonexistent card activated")
	}
	if strings.Contains(strings.ToLower(string(body)), "sql") || strings.Contains(string(body), "pgx") {
		t.Fatalf("internal details leaked: %s", body)
	}
}

func mustSeed(t *testing.T) string {
	t.Helper()
	s, err := crypto.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
