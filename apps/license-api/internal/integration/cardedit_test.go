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

// TestCustomDurationBatch 自定义天数直接制卡（自动建套餐）+ 激活后到期 = +15 天。
func TestCustomDurationBatch(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)
	days := 15

	st, body := e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": "", "duration_days": days,
		"kind": "license", "quantity": 2, "note": "15天自定义",
	})
	if st != 201 {
		t.Fatalf("custom batch: %d %s", st, body)
	}
	var batch struct {
		Cards []string `json:"cards"`
	}
	_ = json.Unmarshal(body, &batch)
	if len(batch.Cards) != 2 {
		t.Fatal("cards missing")
	}

	dev := newDevice(t, e)
	st, body = dev.activate(t, batch.Cards[0], "cdfp", comp("cdfp"))
	if st != 200 {
		t.Fatalf("activate: %d %s", st, body)
	}
	var act struct {
		LicenseID string `json:"license_id"`
	}
	_ = json.Unmarshal(body, &act)
	st, body = e.admin.get(t, "/admin/v1/licenses/"+act.LicenseID)
	var detail struct {
		License struct {
			ExpiresAt string `json:"expires_at"`
		} `json:"license"`
	}
	_ = json.Unmarshal(body, &detail)
	got, err := time.Parse(time.RFC3339, detail.License.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expiry: %v", err)
	}
	diff := got.Sub(time.Now().AddDate(0, 0, days))
	if diff < -time.Hour || diff > time.Hour {
		t.Fatalf("expiry not +15d: %v (diff %v)", detail.License.ExpiresAt, diff)
	}

	// agent 不能用自定义时长（防 0 元绕过计费）
	st, body = e.admin.post(t, "/admin/v1/agents", map[string]any{"name": fmt.Sprintf("cag-%d", time.Now().UnixNano())})
	var agent struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &agent)
	agentUser := fmt.Sprintf("cu%d", time.Now().UnixNano()%100000)
	e.admin.post(t, "/admin/v1/admins", map[string]any{
		"username": agentUser, "display_name": "x", "password": "agent-password-123",
		"role": "agent", "agent_id": agent.ID,
	})
	ag := newAdminSession(t, e, agentUser, "agent-password-123")
	st, body = ag.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": "", "duration_days": 7,
		"kind": "license", "quantity": 1,
	})
	if st == 201 {
		t.Fatal("agent custom duration must be rejected")
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
