package argon2id

import (
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	p := Params{MemoryKiB: 8192, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16} // 测试用轻量参数
	h, err := Hash("correct horse battery staple", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=") {
		t.Fatalf("bad PHC prefix: %s", h)
	}
	ok, err := Verify("correct horse battery staple", h)
	if err != nil || !ok {
		t.Fatalf("verify failed: %v", err)
	}
	ok, _ = Verify("wrong password", h)
	if ok {
		t.Fatal("wrong password accepted")
	}
	// 相同口令两次哈希必须产生不同盐
	h2, _ := Hash("correct horse battery staple", p)
	if h == h2 {
		t.Fatal("salt reuse detected")
	}
}

func TestVerifyBadFormat(t *testing.T) {
	if _, err := Verify("x", "$bcrypt$whatever"); err == nil {
		t.Fatal("bad format accepted")
	}
}
