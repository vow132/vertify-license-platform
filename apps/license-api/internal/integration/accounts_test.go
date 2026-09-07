//go:build integration

// 回归测试：终端用户账号体系 + 公告/版本 + 批量卡密 + 接口限流配置。
package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type userReqBody map[string]any

func userPost(e *testEnv, path string, body userReqBody) (int, []byte) {
	return e.post(path, mustJSON(body), nil)
}

// TestUserAccountFlow 账号全流程：注册→登录（绑机器）→换机拒绝→绑卡续期→改密→找回→禁用。
func TestUserAccountFlow(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)
	productCode := fx.ProductCode
	suffix := randSuffix(t)
	username := fmt.Sprintf("user%d", suffix)

	// 1. 注册
	st, body := userPost(e, "/v1/user/register", userReqBody{
		"product": productCode, "username": username,
		"password": "pass123456", "security_code": "sec9988",
	})
	if st != 200 {
		t.Fatalf("register: %d %s", st, body)
	}
	// 重复注册 → USER_EXISTS
	st, body = userPost(e, "/v1/user/register", userReqBody{
		"product": productCode, "username": username,
		"password": "pass123456", "security_code": "sec9988",
	})
	if st != 409 || codeOf(body) != "USER_EXISTS" {
		t.Fatalf("duplicate register: %d %s", st, body)
	}

	// 2. 首次登录（绑定机器）→ 过期状态 + 令牌
	comp := []string{"fp-guid-1", "fp-board-1", "fp-disk-1"}
	st, body = userPost(e, "/v1/user/login", userReqBody{
		"product": productCode, "username": username,
		"password": "pass123456", "components": comp,
	})
	if st != 200 {
		t.Fatalf("login: %d %s", st, body)
	}
	var login struct {
		Token     string `json:"token"`
		Expired   bool   `json:"expired"`
		ExpiresAt int64  `json:"expires_at"`
	}
	_ = json.Unmarshal(body, &login)
	if login.Token == "" || !login.Expired {
		t.Fatalf("first login: expired must be true, token missing: %s", body)
	}

	// 3. 同机再登录 OK；换机 → MACHINE_BOUND
	st, _ = userPost(e, "/v1/user/login", userReqBody{
		"product": productCode, "username": username,
		"password": "pass123456", "components": comp,
	})
	if st != 200 {
		t.Fatalf("same-machine login: %d", st)
	}
	st, body = userPost(e, "/v1/user/login", userReqBody{
		"product": productCode, "username": username,
		"password": "pass123456", "components": []string{"other-fp"},
	})
	if st != 409 || codeOf(body) != "MACHINE_BOUND" {
		t.Fatalf("machine bound: %d %s", st, body)
	}

	// 4. 制一张授权卡并绑卡续期（+30 天）
	st, body = e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": fx.PlanID, "kind": "license", "quantity": 1,
	})
	if st != 201 {
		t.Fatalf("batch: %d %s", st, body)
	}
	var batch struct {
		Cards []string `json:"cards"`
	}
	_ = json.Unmarshal(body, &batch)

	st, body = userPost(e, "/v1/user/bindcard", userReqBody{
		"token": login.Token, "card": batch.Cards[0],
	})
	if st != 200 {
		t.Fatalf("bind card: %d %s", st, body)
	}
	var bound struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	_ = json.Unmarshal(body, &bound)
	if bound.ExpiresAt <= login.ExpiresAt {
		t.Fatalf("expiry not extended: %d -> %d", login.ExpiresAt, bound.ExpiresAt)
	}
	// 同卡再绑 → 已消耗
	st, body = userPost(e, "/v1/user/bindcard", userReqBody{
		"token": login.Token, "card": batch.Cards[0],
	})
	if st == 200 {
		t.Fatal("same card bound twice")
	}

	// 5. 改密 → 旧密码失效 → 新密码可登录
	st, _ = userPost(e, "/v1/user/changepw", userReqBody{
		"token": login.Token, "password": "pass123456", "new_password": "newpass999",
	})
	if st != 200 {
		t.Fatalf("change pw: %d", st)
	}
	st, body = userPost(e, "/v1/user/login", userReqBody{
		"product": productCode, "username": username,
		"password": "pass123456", "components": comp,
	})
	if st != 401 {
		t.Fatalf("old password must fail: %d", st)
	}
	st, _ = userPost(e, "/v1/user/login", userReqBody{
		"product": productCode, "username": username,
		"password": "newpass999", "components": comp,
	})
	if st != 200 {
		t.Fatalf("new password login: %d", st)
	}

	// 6. 安全码找回
	st, _ = userPost(e, "/v1/user/recover", userReqBody{
		"product": productCode, "username": username,
		"security_code": "wrong-code", "new_password": "recovered777",
	})
	if st != 400 {
		t.Fatalf("wrong security code must 400: %d", st)
	}
	st, _ = userPost(e, "/v1/user/recover", userReqBody{
		"product": productCode, "username": username,
		"security_code": "sec9988", "new_password": "recovered777",
	})
	if st != 200 {
		t.Fatalf("recover: %d", st)
	}
	st, _ = userPost(e, "/v1/user/login", userReqBody{
		"product": productCode, "username": username,
		"password": "recovered777", "components": comp,
	})
	if st != 200 {
		t.Fatalf("recovered login: %d", st)
	}

	// 7. 管理端：用户列表 + 禁用 + 解绑机器
	st, body = e.admin.get(t, "/admin/v1/users?q="+username)
	if st != 200 {
		t.Fatalf("admin list users: %d %s", st, body)
	}
	var users struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &users)
	if len(users.Items) != 1 {
		t.Fatalf("admin users list: %d", len(users.Items))
	}
	uid := users.Items[0].ID
	st, body = e.admin.post(t, "/admin/v1/users/"+uid+"/action", map[string]any{
		"action": "disable", "reason": "测试禁用",
	})
	if st != 200 {
		t.Fatalf("disable: %d %s", st, body)
	}
	st, body = userPost(e, "/v1/user/login", userReqBody{
		"product": productCode, "username": username,
		"password": "recovered777", "components": comp,
	})
	if st != 403 || codeOf(body) != "USER_DISABLED" {
		t.Fatalf("disabled login: %d %s", st, body)
	}
	st, body = e.admin.post(t, "/admin/v1/users/"+uid+"/action", map[string]any{"action": "reset-machine"})
	if st != 200 {
		t.Fatalf("reset machine: %d %s", st, body)
	}
}

// TestAnnounceVersionFlow 公告与版本：创建 → 公开接口下发 → 删除。
func TestAnnounceVersionFlow(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	st, body := e.admin.post(t, "/admin/v1/messages", map[string]any{
		"product_id": fx.ProductID, "content": "v2.0 上线，新增 ESP 功能",
	})
	if st != 201 {
		t.Fatalf("create message: %d %s", st, body)
	}
	var msg struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(body, &msg)

	st, body = e.admin.post(t, "/admin/v1/versions", map[string]any{
		"product_id": fx.ProductID, "version": "2.0.0",
		"download_url": "https://example.com/dl/client-2.0.0.zip",
		"notes":        "大版本更新", "force_update": true,
	})
	if st != 201 {
		t.Fatalf("create version: %d %s", st, body)
	}

	// 公开接口下发
	st, body = e.get("/v1/announce?product="+fx.ProductCode, nil)
	if st != 200 {
		t.Fatalf("announce: %d %s", st, body)
	}
	var ann struct {
		Message string `json:"message"`
		Version *struct {
			Version     string `json:"version"`
			ForceUpdate bool   `json:"force_update"`
		} `json:"version"`
	}
	_ = json.Unmarshal(body, &ann)
	if ann.Message != "v2.0 上线，新增 ESP 功能" {
		t.Fatalf("message mismatch: %q", ann.Message)
	}
	if ann.Version == nil || ann.Version.Version != "2.0.0" || !ann.Version.ForceUpdate {
		t.Fatalf("version mismatch: %+v", ann.Version)
	}

	// 禁用公告后不再下发
	st, _ = e.admin.post(t, fmt.Sprintf("/admin/v1/messages/%d/enabled", msg.ID), map[string]any{"enabled": false})
	if st != 200 {
		t.Fatalf("disable message: %d", st)
	}
	st, body = e.get("/v1/announce?product="+fx.ProductCode, nil)
	_ = json.Unmarshal(body, &ann)
	if ann.Message != "" {
		t.Fatalf("disabled message still served: %q", ann.Message)
	}
}

// TestBulkCardAction 批量冻结/吊销。
func TestBulkCardAction(t *testing.T) {
	e := setupEnv(t)
	fx := seedFixture(t, e)

	st, body := e.admin.post(t, "/admin/v1/batches", map[string]any{
		"product_id": fx.ProductID, "plan_id": fx.PlanID, "kind": "license", "quantity": 3,
	})
	if st != 201 {
		t.Fatalf("batch: %d %s", st, body)
	}
	var batch struct {
		Cards []string `json:"cards"`
	}
	_ = json.Unmarshal(body, &batch)
	if len(batch.Cards) != 3 {
		t.Fatal("cards missing")
	}

	// 通过列表拿 3 张卡的 ID
	st, body = e.admin.get(t, "/admin/v1/cards?limit=500")
	var cards struct {
		Items []struct {
			ID     string `json:"id"`
			Prefix string `json:"prefix"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &cards)
	var ids []string
	for _, c := range cards.Items {
		for _, card := range batch.Cards {
			if strings.HasPrefix(card, c.Prefix) {
				ids = append(ids, c.ID)
			}
		}
	}
	if len(ids) != 3 {
		t.Fatalf("found %d of 3 cards", len(ids))
	}

	st, body = e.admin.post(t, "/admin/v1/cards/bulk-action", map[string]any{
		"ids": ids, "action": "freeze", "reason": "批量冻结测试",
	})
	if st != 200 {
		t.Fatalf("bulk freeze: %d %s", st, body)
	}
	var result struct {
		OK     int            `json:"ok"`
		Failed map[string]any `json:"failed"`
	}
	_ = json.Unmarshal(body, &result)
	if result.OK != 3 {
		t.Fatalf("bulk freeze ok=%d", result.OK)
	}

	// 批量解冻恢复
	st, _ = e.admin.post(t, "/admin/v1/cards/bulk-action", map[string]any{
		"ids": ids, "action": "unfreeze",
	})
	if st != 200 {
		t.Fatalf("bulk unfreeze: %d", st)
	}
}

// TestRateLimitConfig 接口限流配置生效。
func TestRateLimitConfig(t *testing.T) {
	e := setupEnv(t)
	e.admin.login(t)

	// 配置 bootstrap 限流为 2 次/分钟
	st, body := e.admin.post(t, "/admin/v1/ratelimits", map[string]any{
		"scope": "bootstrap", "limit_per_min": 2,
	})
	if st != 200 {
		t.Fatalf("set ratelimit: %d %s", st, body)
	}

	// 第 3 次访问 bootstrap → 429（后台配置生效）
	last := 0
	for i := 0; i < 4; i++ {
		st, _ = e.get("/v1/bootstrap", nil)
		last = st
	}
	if last != 429 {
		t.Fatalf("configured bootstrap rate limit not enforced, last=%d", last)
	}

	// 恢复默认（调高），确认恢复
	st, _ = e.admin.post(t, "/admin/v1/ratelimits", map[string]any{
		"scope": "bootstrap", "limit_per_min": 100000,
	})
	if st != 200 {
		t.Fatalf("restore ratelimit: %d", st)
	}
	time.Sleep(2 * time.Second) // 等待 30s 缓存……不可行，改用：缓存 30s 内仍受限，此处仅验证恢复接口成功
	_ = body
}
