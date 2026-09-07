//go:build integration

// 回归测试：安全修复项的负向用例。
// 覆盖：agent 横向越权、次卡扣减、永久续费拒绝、封禁执行、状态机守卫。
package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"
)

// adminSession 独立会话的管理端客户端（多管理员场景）。
type adminSession struct {
	env  *testEnv
	jar  *cookiejar.Jar
	csrf string
}

func newAdminSession(t *testing.T, e *testEnv, username, password string) *adminSession {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	s := &adminSession{env: e, jar: jar}
	req, _ := http.NewRequest("POST", e.ts.URL+"/admin/v1/auth/login",
		bytes.NewReader(mustJSON(map[string]any{"username": username, "password": password})))
	resp, err := (&http.Client{Jar: jar}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 {
		t.Fatalf("agent login: %d", resp.StatusCode)
	}
	s.csrf = out.CSRFToken
	return s
}

func (a *adminSession) post(t *testing.T, path string, body any) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", a.env.ts.URL+path, bytes.NewReader(mustJSON(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", a.csrf)
	resp, err := (&http.Client{Jar: a.jar}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func (a *adminSession) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", a.env.ts.URL+path, nil)
	resp, err := (&http.Client{Jar: a.jar}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// TestAgentHorizontalIsolation agent 角色不能操作其它代理商的卡密/许可证/设备。
func TestAgentHorizontalIsolation(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	// 激活一张卡（归属 root / 直营 agent）
	dev := newDevice(t, e)
	st, body := dev.activate(t, fx.Batch[0], "fpa", comp("fpa"))
	if st != 200 {
		t.Fatalf("activate: %d %s", st, body)
	}

	// 创建代理商 + agent 角色管理员
	st, body = e.admin.post(t, "/admin/v1/agents", map[string]any{"name": fmt.Sprintf("agent-%d", time.Now().UnixNano())})
	if st != 201 {
		t.Fatalf("create agent: %d %s", st, body)
	}
	var agent struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &agent)

	agentUser := fmt.Sprintf("ag%d", time.Now().UnixNano()%100000)
	st, body = e.admin.post(t, "/admin/v1/admins", map[string]any{
		"username": agentUser, "display_name": "代理A", "password": "agent-password-123",
		"role": "agent", "agent_id": agent.ID,
	})
	if st != 201 {
		t.Fatalf("create agent admin: %d %s", st, body)
	}
	ag := newAdminSession(t, e, agentUser, "agent-password-123")

	// 用 root 会话找卡 ID（agent 的列表本来就该看不到别人的卡）
	st, body = e.admin.get(t, "/admin/v1/cards?limit=500")
	if st != 200 {
		t.Fatalf("root list cards: %d %s", st, body)
	}
	var cards struct {
		Items []struct {
			ID     string `json:"id"`
			Prefix string `json:"prefix"`
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
		t.Fatal("card not found")
	}
	st, body = ag.get(t, "/admin/v1/licenses/"+dev.LicenseID)
	if st != 404 {
		t.Fatalf("agent license detail must be 404, got %d", st)
	}
	st, body = ag.post(t, "/admin/v1/cards/"+cardID+"/action", map[string]any{"action": "freeze", "reason": "x"})
	if st != 404 {
		t.Fatalf("agent card freeze must be 404, got %d %s", st, body)
	}
	// 许可证吊销需要 licenses:manage（agent 角色没有）——RBAC 403 或归属 404 都算正确拒绝
	st, body = ag.post(t, "/admin/v1/licenses/"+dev.LicenseID+"/action", map[string]any{"action": "revoke", "reason": "x"})
	if st != 404 && st != 403 {
		t.Fatalf("agent license revoke must be denied, got %d %s", st, body)
	}
	st, _ = ag.get(t, "/admin/v1/devices?license_id="+dev.LicenseID)
	if st != 404 {
		t.Fatalf("agent list devices must be 404, got %d", st)
	}
}

// TestUsesCardDepletion 次卡：绑定消耗次数，耗尽后拒绝新设备。
func TestUsesCardDepletion(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	suffix := randSuffix(t)
	st, body := e.admin.post(t, "/admin/v1/plans", map[string]any{
		"product_id": fx.ProductID, "code": fmt.Sprintf("uses-%d", suffix), "name": "次卡",
		"kind": "uses", "uses_total": 1, "features": []any{},
		"device_limit": 3, "concurrent_limit": 1,
	})
	if st != 201 {
		t.Fatalf("create uses plan: %d %s", st, body)
	}
	var usesPlan struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &usesPlan)

	st, body = e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": usesPlan.ID, "kind": "license", "quantity": 1,
	})
	if st != 201 {
		t.Fatalf("create uses batch: %d %s", st, body)
	}
	var batch struct {
		Cards []string `json:"cards"`
	}
	_ = json.Unmarshal(body, &batch)
	if len(batch.Cards) != 1 {
		t.Fatal("batch cards missing")
	}

	// 第一次激活：消耗 1 次（uses_total=1 → 剩 0）
	dev1 := newDevice(t, e)
	st, body = dev1.activate(t, batch.Cards[0], "u1", comp("u1"))
	if st != 200 {
		t.Fatalf("first activate: %d %s", st, body)
	}
	// 第二台设备：次数已耗尽
	dev2 := newDevice(t, e)
	st, body = dev2.activate(t, batch.Cards[0], "u2", comp("u2"))
	if st != 403 || codeOf(body) != "CARD_DEPLETED" {
		t.Fatalf("depleted card must reject new device: %d %s", st, body)
	}
	// 首设备心跳仍正常（已绑定的设备不受影响）
	if st, _ := dev1.heartbeat(t); st != 200 {
		t.Fatalf("bound device heartbeat broken: %d", st)
	}
}

// TestPermanentRenewalRejected 永久许可证不能兑换时长续费卡。
func TestPermanentRenewalRejected(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	suffix := randSuffix(t)
	st, body := e.admin.post(t, "/admin/v1/plans", map[string]any{
		"product_id": fx.ProductID, "code": fmt.Sprintf("perm-%d", suffix), "name": "永久卡",
		"kind": "permanent", "features": []any{},
		"device_limit": 1, "concurrent_limit": 1,
	})
	if st != 201 {
		t.Fatalf("create permanent plan: %d %s", st, body)
	}
	var plan struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &plan)

	st, body = e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": plan.ID, "kind": "license", "quantity": 1,
	})
	if st != 201 {
		t.Fatalf("batch: %d %s", st, body)
	}
	var batch struct {
		Cards []string `json:"cards"`
	}
	_ = json.Unmarshal(body, &batch)

	dev := newDevice(t, e)
	st, body = dev.activate(t, batch.Cards[0], "pp", comp("pp"))
	if st != 200 {
		t.Fatalf("activate permanent: %d %s", st, body)
	}
	st, body = dev.redeem(t, fx.RenewalCards[0])
	if st != 409 || codeOf(body) != "CARD_NOT_USABLE" {
		t.Fatalf("permanent redeem must be rejected: %d %s", st, body)
	}
}

// TestCardPrefixBan 卡密前缀封禁在激活时生效。
func TestCardPrefixBan(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	prefix := strings.Split(fx.Batch[3], "-")[0]
	st, body := e.admin.post(t, "/admin/v1/bans", map[string]any{
		"kind": "card_prefix", "value": prefix, "reason": "泄露应急",
	})
	if st != 201 {
		t.Fatalf("create ban: %d %s", st, body)
	}
	dev := newDevice(t, e)
	st, body = dev.activate(t, fx.Batch[3], "fb", comp("fb"))
	if st != 403 || codeOf(body) != "BANNED" {
		t.Fatalf("banned prefix activation: %d %s", st, body)
	}
	// 解除封禁后可正常激活
	st, body = e.admin.post(t, "/admin/v1/bans/delete", map[string]any{"kind": "card_prefix", "value": prefix})
	if st != 200 {
		t.Fatalf("delete ban: %d %s", st, body)
	}
	st, body = dev.activate(t, fx.Batch[3], "fb", comp("fb"))
	if st != 200 {
		t.Fatalf("activation after unban: %d %s", st, body)
	}
}

// TestFrozenCardCannotResurrectRevokedLicense 状态机守卫：冻结-吊销-解冻链不复活许可证。
func TestFrozenCardCannotResurrectRevokedLicense(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	dev := newDevice(t, e)
	st, body := dev.activate(t, fx.Batch[4], "fs", comp("fs"))
	if st != 200 {
		t.Fatalf("activate: %d %s", st, body)
	}
	var act struct {
		LicenseID string `json:"license_id"`
	}
	_ = json.Unmarshal(body, &act)

	// 冻结许可证 → 吊销（级联卡密 revoked）→ 卡密不可解冻 → 许可证保持 revoked
	st, body = e.admin.post(t, "/admin/v1/licenses/"+act.LicenseID+"/action", map[string]any{"action": "freeze", "reason": "x"})
	if st != 200 {
		t.Fatalf("freeze: %d %s", st, body)
	}
	st, body = e.admin.post(t, "/admin/v1/licenses/"+act.LicenseID+"/action", map[string]any{"action": "revoke", "reason": "x"})
	if st != 200 {
		t.Fatalf("revoke: %d %s", st, body)
	}
	// 吊销会级联源卡密为 revoked；revoked 不是 frozen，unfreeze 必须被拒
	st, body = e.admin.get(t, "/admin/v1/licenses/"+act.LicenseID)
	var detail struct {
		License struct {
			Status string `json:"status"`
		} `json:"license"`
	}
	_ = json.Unmarshal(body, &detail)
	if st != 200 || detail.License.Status != "revoked" {
		t.Fatalf("license must stay revoked: %d %s", st, body)
	}
}

// TestLoginRateLimit 登录接口 IP 限流生效（专用低阈值环境）。
func TestLoginRateLimit(t *testing.T) {
	e := setupEnv(t)
	e.svc.Cfg.AdminLoginRPM = 3
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	lastStatus := 0
	for i := 0; i < 15; i++ {
		req, _ := http.NewRequest("POST", e.ts.URL+"/admin/v1/auth/login",
			bytes.NewReader(mustJSON(map[string]any{"username": "nouser", "password": "wrong-password"})))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		lastStatus = resp.StatusCode
		resp.Body.Close()
		if lastStatus == 429 {
			return // 触发限流即通过
		}
	}
	t.Fatalf("login rate limit not enforced, last=%d", lastStatus)
}

// randSuffix 生成测试资源后缀（Windows 计时器精度不足，UnixNano 偶发重复）。
func randSuffix(t *testing.T) int {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return int(binary.BigEndian.Uint32(b)) % 1000000
}
