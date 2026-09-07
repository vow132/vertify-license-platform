//go:build integration

// 端到端集成测试：需要本地 PostgreSQL 与 Redis。
//
//	VFT_TEST_DATABASE_URL=postgres://vertify:vertify@127.0.0.1:54329/vertify_test?sslmode=disable \
//	VFT_TEST_REDIS_URL=redis://127.0.0.1:6399/1 go test -tags integration ./internal/integration/ -v
//
// 覆盖：制卡 → 激活（信封加密+设备签名）→ 心跳租约 → 防重放 → 冻结/吊销传播 →
// 设备名额 → 解绑/重绑 → 续费卡兑换 → 限流 → 越权。
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vertify/license-platform/internal/cache"
	"github.com/vertify/license-platform/internal/config"
	"github.com/vertify/license-platform/internal/crypto"
	"github.com/vertify/license-platform/internal/httpapi"
	"github.com/vertify/license-platform/internal/service"
	"github.com/vertify/license-platform/internal/store"
)

// ===== 测试环境 =====

type testEnv struct {
	ts     *httptest.Server
	client *http.Client
	admin  *adminClient
	svc    *service.Services
	cache  *cache.Cache
	keys   crypto.Signer
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	if os.Getenv("VFT_TEST_DATABASE_URL") == "" {
		t.Skip("integration test: set VFT_TEST_DATABASE_URL / VFT_TEST_REDIS_URL")
	}
	dbURL := os.Getenv("VFT_TEST_DATABASE_URL")
	redisURL := os.Getenv("VFT_TEST_REDIS_URL")

	ctx := context.Background()
	if err := store.Migrate(ctx, dbURL, "../../../../db/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	ca, err := cache.New(ctx, redisURL)
	if err != nil {
		t.Fatal(err)
	}
	// 每个测试结束时清空瞬态（限流计数/nonce/在线集合），消除跨测试窗口竞态
	t.Cleanup(func() {
		_ = ca.FlushDB(ctx)
		ca.Close()
	})

	seedA, _ := crypto.GenerateSeed()
	seedB, _ := crypto.GenerateSeed()
	signer, err := crypto.NewLocalSigner(map[string]string{"test-a": seedA, "test-b": seedB}, "test-a")
	if err != nil {
		t.Fatal(err)
	}
	kex, _ := crypto.NewKexKeyPair("kex-test-a", true)
	if err := st.Q().UpsertKexKey(ctx, kex.KID, kex.PubB64, "A256GCM", true); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Env:                      "dev",
		CardHMACKey:              randBytes(t, 32),
		AdminSessionTTL:          time.Hour,
		ReplayWindow:             5 * time.Minute,
		MaxClockSkew:             2 * time.Minute,
		ActivateRatelimitPerMin:  1000,
		HeartbeatRatelimitPerMin: 1000,
		BootstrapRatelimitPerMin: 1000,
		AdminLoginRPM:            1000,
	}
	svc, err := service.New(cfg, signer, []*crypto.KexKeyPair{kex}, st, ca)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/", httpapi.ClientRouter(svc, nil))
	mux.Handle("/admin/", httpapi.AdminRouter(svc, nil))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	env := &testEnv{ts: ts, client: &http.Client{Jar: jar}, svc: svc, cache: ca, keys: signer}
	env.admin = &adminClient{env: env}
	return env
}

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// ===== HTTP 基础 =====

func (e *testEnv) post(path string, body []byte, hdr map[string]string) (int, []byte) {
	req, _ := http.NewRequest("POST", e.ts.URL+path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return -1, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *testEnv) get(path string, hdr map[string]string) (int, []byte) {
	req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return -1, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// ===== 管理端客户端 =====

type adminClient struct {
	env  *testEnv
	csrf string
}

func (a *adminClient) login(t *testing.T) {
	t.Helper()
	st, body := a.env.post("/admin/v1/auth/login", mustJSON(map[string]any{
		"username": "root", "password": "root-password-123",
	}), nil)
	if st != 200 {
		t.Fatalf("admin login: %d %s", st, body)
	}
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(body, &out)
	a.csrf = out.CSRFToken
}

func (a *adminClient) post(t *testing.T, path string, body any) (int, []byte) {
	t.Helper()
	return a.env.post(path, mustJSON(body), map[string]string{"X-CSRF-Token": a.csrf})
}

func (a *adminClient) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	return a.env.get(path, nil)
}

// ===== 设备客户端（协议参考实现，C++ SDK 与其保持一致） =====

type deviceClient struct {
	env    *testEnv
	priv   ed25519.PrivateKey
	pubB64 string
	seq    int64
	// 激活后状态
	LicenseID string
	DeviceID  string
	Lease     string
}

func newDevice(t *testing.T, e *testEnv) *deviceClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &deviceClient{
		env:    e,
		priv:   priv,
		pubB64: base64.RawURLEncoding.EncodeToString(pub),
	}
}

// deviceAuthHeader 构造 PoP 签名头。
func (d *deviceClient) deviceAuthHeader(method, path string, body []byte, ts int64, nonce string, seq int64) string {
	msg := crypto.DeviceAuthMessage(method, path, ts, nonce, seq, body)
	sig := ed25519.Sign(d.priv, msg)
	return fmt.Sprintf("v1 pub=%s ts=%d nonce=%s seq=%d sig=%s",
		d.pubB64, ts, nonce, seq, base64.RawURLEncoding.EncodeToString(sig))
}

// sealEnvelope 按 bootstrap 下发的 KEX 公钥封装载荷（Go 版 SDK 行为）。
func (d *deviceClient) sealEnvelope(t *testing.T, purpose string, payload any) []byte {
	t.Helper()
	st, body := d.env.get("/v1/bootstrap", nil)
	if st != 200 {
		t.Fatalf("bootstrap: %d", st)
	}
	var boot struct {
		KexKeys []struct {
			KID    string `json:"kid"`
			Pub    string `json:"pub"`
			Alg    string `json:"alg"`
			Active bool   `json:"active"`
		} `json:"kex_keys"`
	}
	if err := json.Unmarshal(body, &boot); err != nil {
		t.Fatal(err)
	}
	var kid, pub, alg string
	for _, k := range boot.KexKeys {
		if k.Active {
			kid, pub, alg = k.KID, k.Pub, k.Alg
		}
	}
	if kid == "" {
		t.Fatal("no active kex key")
	}
	pt, _ := json.Marshal(payload)
	env, err := sealWithEphemeral(t, kid, pub, alg, pt, crypto.AADContext(purpose))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// sealWithEphemeral 与 crypto.SealEnvelope 相同，但这里从 bootstrap 数据出发，
// 验证协议不依赖服务端内部结构。
func sealWithEphemeral(t *testing.T, kid, serverPubB64, alg string, pt, aad []byte) ([]byte, error) {
	t.Helper()
	// 直接复用服务端 crypto 包的封装实现（同一算法集）
	return crypto.SealEnvelope(kid, serverPubB64, alg, pt, aad)
}

func (d *deviceClient) activate(t *testing.T, card, fp string, components []string) (int, []byte) {
	t.Helper()
	payload := map[string]any{
		"card":           card,
		"components":     components,
		"device_pub":     d.pubB64,
		"trust_level":    "tpm",
		"client_version": "1.0.0",
	}
	env := d.sealEnvelope(t, "activate", payload)
	ts := time.Now().Unix()
	nonce := mustNonce(t)
	hdr := d.deviceAuthHeader("POST", "/v1/activate", env, ts, nonce, 0)
	st, body := d.env.post("/v1/activate", env, map[string]string{"X-Vft-Device-Auth": hdr})
	// 自动记录激活返回的绑定信息
	if st == 200 {
		var act struct {
			LicenseID string `json:"license_id"`
			DeviceID  string `json:"device_id"`
			Lease     string `json:"lease"`
		}
		if json.Unmarshal(body, &act) == nil {
			d.LicenseID, d.DeviceID, d.Lease = act.LicenseID, act.DeviceID, act.Lease
		}
	}
	return st, body
}

func (d *deviceClient) heartbeat(t *testing.T) (int, []byte) {
	t.Helper()
	d.seq++
	body := mustJSON(map[string]any{"device_id": d.DeviceID, "client_version": "1.0.0"})
	ts := time.Now().Unix()
	nonce := mustNonce(t)
	hdr := d.deviceAuthHeader("POST", "/v1/heartbeat", body, ts, nonce, d.seq)
	return d.env.post("/v1/heartbeat", body, map[string]string{"X-Vft-Device-Auth": hdr})
}

// heartbeatRaw 完全由调用方控制序列号/nonce/时间戳/请求体（负向测试用）。
func (d *deviceClient) heartbeatRaw(t *testing.T, body []byte, ts int64, nonce string, seq int64) (int, []byte) {
	t.Helper()
	hdr := d.deviceAuthHeader("POST", "/v1/heartbeat", body, ts, nonce, seq)
	return d.env.post("/v1/heartbeat", body, map[string]string{"X-Vft-Device-Auth": hdr})
}

func (d *deviceClient) deactivate(t *testing.T) (int, []byte) {
	t.Helper()
	body := mustJSON(map[string]any{"device_id": d.DeviceID})
	ts := time.Now().Unix()
	nonce := mustNonce(t)
	hdr := d.deviceAuthHeader("POST", "/v1/deactivate", body, ts, nonce, d.seq+1000)
	d.seq += 1000
	return d.env.post("/v1/deactivate", body, map[string]string{"X-Vft-Device-Auth": hdr})
}

func (d *deviceClient) redeem(t *testing.T, card string) (int, []byte) {
	t.Helper()
	payload := map[string]any{"card": card}
	env := d.sealEnvelope(t, "redeem", payload)
	ts := time.Now().Unix()
	nonce := mustNonce(t)
	d.seq++
	hdr := d.deviceAuthHeader("POST", "/v1/redeem", env, ts, nonce, d.seq)
	return d.env.post("/v1/redeem", env, map[string]string{"X-Vft-Device-Auth": hdr})
}

func mustNonce(t *testing.T) string {
	t.Helper()
	b := randBytes(t, 16)
	return base64.RawURLEncoding.EncodeToString(b)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ===== 测试固件：产品/套餐/卡密 =====

type fixture struct {
	ProductID    string
	ProductCode  string
	PlanID       string
	PlanIDRenew  string
	Batch        []string // 明文卡密
	RenewalCards []string
}

func seedFixture(t *testing.T, e *testEnv) *fixture {
	suffix := randSuffix(t) // Windows 计时器精度不足，用 crypto/rand 防代码碰撞
	t.Helper()
	// 直接经服务层创建初始管理员（绕过 HTTP 的首启限制）；幂等处理重复运行
	if _, err := e.svc.BootstrapAdmin(context.Background(), "root", "root-password-123", ""); err != nil &&
		!strings.Contains(err.Error(), "23505") {
		t.Fatalf("bootstrap admin: %v", err)
	}
	e.admin.login(t)

	st, body := e.admin.post(t, "/admin/v1/products", map[string]any{"code": fmt.Sprintf("AUX%d", suffix), "name": "辅助工具 Pro"})
	if st != 201 {
		t.Fatalf("create product: %d %s", st, body)
	}
	var prod struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &prod)

	st, body = e.admin.post(t, "/admin/v1/plans", map[string]any{
		"product_id": prod.ID, "code": fmt.Sprintf("monthly-%d", suffix), "name": "月卡",
		"kind": "duration", "duration_days": 30,
		"device_limit": 2, "concurrent_limit": 1,
		"features":                   []string{"aimbot", "esp"},
		"heartbeat_interval_seconds": 60, "lease_ttl_seconds": 300,
	})
	if st != 201 {
		t.Fatalf("create plan: %d %s", st, body)
	}
	var plan struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &plan)

	st, body = e.admin.post(t, "/admin/v1/plans", map[string]any{
		"product_id": prod.ID, "code": fmt.Sprintf("renew-%d", suffix), "name": "续费30天",
		"kind": "duration", "duration_days": 30, "features": []any{},
		"device_limit": 1, "concurrent_limit": 1,
	})
	if st != 201 {
		t.Fatalf("create renewal plan: %d %s", st, body)
	}
	var rplan struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &rplan)

	st, body = e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": prod.ID, "plan_id": plan.ID, "kind": "license", "quantity": 10,
	})
	if st != 201 {
		t.Fatalf("create batch: %d %s", st, body)
	}
	var batch struct {
		Cards []string `json:"cards"`
	}
	_ = json.Unmarshal(body, &batch)

	st, body = e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": prod.ID, "plan_id": rplan.ID, "kind": "renewal", "quantity": 5,
	})
	if st != 201 {
		t.Fatalf("create renewal batch: %d %s", st, body)
	}
	var rbatch struct {
		Cards []string `json:"cards"`
	}
	_ = json.Unmarshal(body, &rbatch)

	return &fixture{
		ProductID: prod.ID, ProductCode: prod.Code, PlanID: plan.ID, PlanIDRenew: rplan.ID,
		Batch: batch.Cards, RenewalCards: rbatch.Cards,
	}
}
