//go:build integration

// 回归测试：代理余额体系。
// 覆盖：无余额制卡被拒 → 充值 → 制卡扣款 → 超额制卡被拒 → 流水记录。
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"
)

// TestAgentBalanceFlow 完整余额业务闭环。
func TestAgentBalanceFlow(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	// 1. 建定价套餐：10 元/张
	suffix := randSuffix(t)
	st, body := e.admin.post(t, "/admin/v1/plans", map[string]any{
		"product_id": fx.ProductID, "code": fmt.Sprintf("priced-%d", suffix), "name": "计费月卡",
		"kind": "duration", "duration_days": 30, "features": []any{},
		"device_limit": 1, "concurrent_limit": 1, "price_cents": 1000,
	})
	if st != 201 {
		t.Fatalf("create priced plan: %d %s", st, body)
	}
	var pricedPlan struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &pricedPlan)

	// 制一批定价卡（归属 root，无代理 → 免费），供后续代理制卡测试外使用
	_ = fx

	// 2. 建代理商 + agent 管理员
	st, body = e.admin.post(t, "/admin/v1/agents", map[string]any{"name": fmt.Sprintf("bal-%d", time.Now().UnixNano())})
	if st != 201 {
		t.Fatalf("create agent: %d %s", st, body)
	}
	var agent struct {
		ID           string `json:"id"`
		BalanceCents int64  `json:"balance_cents"`
	}
	_ = json.Unmarshal(body, &agent)
	if agent.BalanceCents != 0 {
		t.Fatalf("new agent balance must be 0, got %d", agent.BalanceCents)
	}
	agentUser := fmt.Sprintf("bal%d", time.Now().UnixNano()%100000)
	st, body = e.admin.post(t, "/admin/v1/admins", map[string]any{
		"username": agentUser, "display_name": "计费代理", "password": "agent-password-123",
		"role": "agent", "agent_id": agent.ID,
	})
	if st != 201 {
		t.Fatalf("create agent admin: %d %s", st, body)
	}
	ag := newAdminSession(t, e, agentUser, "agent-password-123")

	// 2.5 开通代理商对产品的制卡权限（未开通时制卡直接 403）
	st, body = ag.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": pricedPlan.ID, "kind": "license", "quantity": 1,
	})
	if st != 403 || codeOf(body) != "PRODUCT_NOT_GRANTED" {
		t.Fatalf("ungranted batch must be PRODUCT_NOT_GRANTED: %d %s", st, body)
	}
	st, body = e.admin.post(t, "/admin/v1/agents/"+agent.ID+"/products", map[string]any{
		"product_id": fx.ProductID, "granted": true,
	})
	if st != 200 {
		t.Fatalf("grant product: %d %s", st, body)
	}

	// 3. 零余额制卡 → BALANCE_INSUFFICIENT
	st, body = e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": pricedPlan.ID, "kind": "license", "quantity": 1,
	})
	if st != 201 {
		t.Fatalf("root priced batch: %d %s", st, body)
	}
	st, body = ag.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": pricedPlan.ID, "kind": "license", "quantity": 1,
	})
	if st != 409 || codeOf(body) != "BALANCE_INSUFFICIENT" {
		t.Fatalf("zero-balance batch must be BALANCE_INSUFFICIENT: %d %s", st, body)
	}

	// 4. 总经销充值 50 元
	st, body = e.admin.post(t, "/admin/v1/agents/"+agent.ID+"/balance", map[string]any{
		"amount_yuan": 50, "note": "首充",
	})
	if st != 200 {
		t.Fatalf("topup: %d %s", st, body)
	}
	var bal struct {
		BalanceCents int64 `json:"balance_cents"`
	}
	_ = json.Unmarshal(body, &bal)
	if bal.BalanceCents != 5000 {
		t.Fatalf("balance after topup: %d", bal.BalanceCents)
	}

	// 5. 代理制 3 张（30 元）→ 成功；余额 20 元
	st, body = ag.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": pricedPlan.ID, "kind": "license", "quantity": 3,
	})
	if st != 201 {
		t.Fatalf("agent batch 3: %d %s", st, body)
	}
	st, body = e.admin.get(t, "/admin/v1/agents/"+agent.ID+"/transactions")
	if st != 200 {
		t.Fatalf("list transactions: %d %s", st, body)
	}
	var txs struct {
		Items []struct {
			Kind        string `json:"kind"`
			AmountCents int64  `json:"amount_cents"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &txs)
	if len(txs.Items) < 2 {
		t.Fatalf("transactions missing: %d", len(txs.Items))
	}
	if txs.Items[0].Kind != "batch_purchase" || txs.Items[0].AmountCents != -3000 {
		t.Fatalf("latest tx wrong: %+v", txs.Items[0])
	}
	if txs.Items[1].Kind != "topup" || txs.Items[1].AmountCents != 5000 {
		t.Fatalf("topup tx wrong: %+v", txs.Items[1])
	}

	// 6. 超额制卡（100 张 = 1000 元 > 20 元）→ BALANCE_INSUFFICIENT
	st, body = ag.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": pricedPlan.ID, "kind": "license", "quantity": 100,
	})
	if st != 409 || codeOf(body) != "BALANCE_INSUFFICIENT" {
		t.Fatalf("over-balance batch: %d %s", st, body)
	}

	// 7. 调差扣回 20 元到 0 后再充值校验负余额拒绝（CHECK 约束）
	st, body = e.admin.post(t, "/admin/v1/agents/"+agent.ID+"/balance", map[string]any{
		"amount_yuan": -30, "note": "超额调差",
	})
	if st != 409 {
		t.Fatalf("over-deduct must 409: %d %s", st, body)
	}

	// 8. agent 会话 /me 返回自己余额
	st, body = ag.get(t, "/admin/v1/auth/me")
	if st != 200 {
		t.Fatalf("me: %d", st)
	}
	var me struct {
		BalanceCents int64 `json:"balance_cents"`
	}
	_ = json.Unmarshal(body, &me)
	if me.BalanceCents != 2000 {
		t.Fatalf("me balance: %d", me.BalanceCents)
	}

	_ = bytes.MinRead
	_ = http.DefaultClient
	_ = cookiejar.New
}
