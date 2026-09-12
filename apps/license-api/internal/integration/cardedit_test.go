//go:build integration

// 回归测试：卡密备注编辑 + 自定义时长制卡 + 许可证手动续期。
package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func findCardIDByPrefix(t *testing.T, e *testEnv, prefix string) string {
	t.Helper()
	_, body := e.admin.get(t, "/admin/v1/cards?limit=500")
	var cards struct {
		Items []struct {
			ID     string `json:"id"`
			Prefix string `json:"prefix"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &cards)
	for _, c := range cards.Items {
		if c.Prefix == prefix {
			return c.ID
		}
	}
	return ""
}

func cardNoteByPrefix(t *testing.T, e *testEnv, prefix string) string {
	t.Helper()
	_, body := e.admin.get(t, "/admin/v1/cards?limit=500")
	var cards struct {
		Items []struct {
			Prefix string `json:"prefix"`
			Note   string `json:"note"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &cards)
	for _, c := range cards.Items {
		if c.Prefix == prefix {
			return c.Note
		}
	}
	return ""
}

// TestCardNoteEdit 卡密备注编辑并持久化。
func TestCardNoteEdit(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)
	prefix := strings.Split(fx.Batch[5], "-")[0]
	cardID := findCardIDByPrefix(t, e, prefix)
	if cardID == "" {
		t.Fatal("card not found")
	}

	st, body := e.admin.post(t, "/admin/v1/cards/"+cardID+"/note", map[string]any{
		"note": "已卖给客户张三，微信联系",
	})
	if st != 200 {
		t.Fatalf("set note: %d %s", st, body)
	}
	if got := cardNoteByPrefix(t, e, prefix); got != "已卖给客户张三，微信联系" {
		t.Fatalf("note not persisted: %q", got)
	}
}

// TestPlanLifecycleRules 制卡必须选套餐；退役套餐代理商不可见；退役套餐删除规则。
func TestPlanLifecycleRules(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	// 不带套餐制卡必须拒绝
	st, body := e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": "",
		"kind": "license", "quantity": 1,
	})
	if st == 201 {
		t.Fatal("batch without plan must be rejected")
	}

	// 新建一个套餐并退役：退役后代理商列表不可见
	st, body = e.admin.post(t, "/admin/v1/plans", map[string]any{
		"product_id": fx.ProductID, "code": fmt.Sprintf("tmp-%d", time.Now().UnixNano()%100000),
		"name": "临时套餐", "kind": "duration", "duration_days": 15,
		"device_limit": 1, "concurrent_limit": 1, "features": []string{},
		"heartbeat_interval_seconds": 60, "lease_ttl_seconds": 300,
	})
	if st != 201 {
		t.Fatalf("create tmp plan: %d %s", st, body)
	}
	var tmpPlan struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &tmpPlan)

	// 在套餐上制卡（生成未使用卡），然后退役
	st, body = e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": tmpPlan.ID,
		"kind": "license", "quantity": 3,
	})
	if st != 201 {
		t.Fatalf("batch on tmp plan: %d %s", st, body)
	}
	st, body = e.admin.post(t, "/admin/v1/plans/"+tmpPlan.ID+"/status", map[string]any{"status": "retired"})
	if st != 200 {
		t.Fatalf("retire plan: %d %s", st, body)
	}

	// agent 创建（一步建号）后，套餐列表不得包含退役套餐
	st, body = e.admin.post(t, "/admin/v1/agents", map[string]any{
		"name":             fmt.Sprintf("pl-ag-%d", time.Now().UnixNano()),
		"account_username": fmt.Sprintf("pl%d", randSuffix(t)),
		"account_password": "agent-password-123",
	})
	if st != 201 {
		t.Fatalf("create agent: %d %s", st, body)
	}
	var agentResp struct {
		Account struct {
			Username string `json:"username"`
		} `json:"account"`
	}
	_ = json.Unmarshal(body, &agentResp)
	ag := newAdminSession(t, e, agentResp.Account.Username, "agent-password-123")
	st, body = ag.get(t, "/admin/v1/plans")
	if st != 200 {
		t.Fatalf("agent plans list: %d %s", st, body)
	}
	if strings.Contains(string(body), tmpPlan.ID) {
		t.Fatal("retired plan must be invisible to agents")
	}

	// 未退役的套餐不能直接删
	st, body = e.admin.del(t, "/admin/v1/plans/"+fx.PlanID)
	if st == 200 {
		t.Fatal("active plan delete must be rejected")
	}

	// 退役 + 只有未使用卡：删除时应作废清理这些未使用卡
	st, body = e.admin.del(t, "/admin/v1/plans/"+tmpPlan.ID)
	if st != 200 {
		t.Fatalf("delete retired plan with only unused cards: %d %s", st, body)
	}
}

// TestAdminLicenseExtend 管理员手动续期许可证（30 天套餐 + 7 天 = 37 天）。
func TestAdminLicenseExtend(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)
	dev := newDevice(t, e)
	st, body := dev.activate(t, fx.Batch[6], "exfp", comp("exfp"))
	if st != 200 {
		t.Fatalf("activate: %d %s", st, body)
	}
	var act struct {
		LicenseID string `json:"license_id"`
	}
	_ = json.Unmarshal(body, &act)

	st, body = e.admin.post(t, "/admin/v1/licenses/"+act.LicenseID+"/extend", map[string]any{
		"days": 7, "reason": "客户补偿",
	})
	if st != 200 {
		t.Fatalf("extend: %d %s", st, body)
	}
	var r struct {
		NewExpiry string `json:"new_expiry"`
	}
	_ = json.Unmarshal(body, &r)
	exp, err := time.Parse(time.RFC3339, r.NewExpiry)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := time.Now().AddDate(0, 0, 37)
	diff := exp.Sub(want)
	if diff < -time.Hour || diff > time.Hour {
		t.Fatalf("expiry not +37d: %v", exp)
	}
}
