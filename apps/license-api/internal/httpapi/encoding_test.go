package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeJSONRejectsInvalidEncoding 无效编码必须被拒绝而不是静默替换成 U+FFFD 存库
// （回归：GBK 客户端曾把中文写坏进数据库）。
func TestDecodeJSONRejectsInvalidEncoding(t *testing.T) {
	type req struct {
		Name string `json:"name"`
	}

	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"valid utf8 chinese", `{"name":"辅助工具 Pro"}`, false},
		{"valid utf8 emoji", `{"name":"ok🎉"}`, false},
		{"gbk bytes (invalid utf8)", "{\"name\":\"\u8f85\u52a9\"}\x00", true}, // 占位，下行替换为真实 GBK 字节
		{"lone invalid byte", "{\"name\":\"\xff\xfe\"}", true},
		{"u+fffd replacement char", `{"name":"�"}`, true},
	}
	// 真实 GBK 字节："辅助" 的 GBK 编码为 B8 A8 D6 FA
	cases[2].body = "{\"name\":\"\xb8\xa8\xd6\xfa\"}"

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/x", strings.NewReader(c.body))
			var v req
			err := decodeJSON(r, &v)
			if c.wantErr && err == nil {
				t.Fatalf("invalid encoding accepted: %q", c.body)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("valid encoding rejected: %v", err)
			}
		})
	}
}
