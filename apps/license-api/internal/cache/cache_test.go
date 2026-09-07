package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newTestCache(t *testing.T) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := New(context.Background(), "redis://"+mr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, mr
}

func TestConsumeNonce(t *testing.T) {
	c, mr := newTestCache(t)
	ctx := context.Background()
	ok, err := c.ConsumeNonce(ctx, "heartbeat", "n1", time.Minute)
	if err != nil || !ok {
		t.Fatalf("first use must succeed: ok=%v err=%v", ok, err)
	}
	ok, _ = c.ConsumeNonce(ctx, "heartbeat", "n1", time.Minute)
	if ok {
		t.Fatal("replay accepted")
	}
	// 不同 scope 不冲突
	ok, _ = c.ConsumeNonce(ctx, "activate", "n1", time.Minute)
	if !ok {
		t.Fatal("scope isolation broken")
	}
	mr.FastForward(2 * time.Minute)
	ok, _ = c.ConsumeNonce(ctx, "heartbeat", "n1", time.Minute)
	if !ok {
		t.Fatal("nonce should expire")
	}
}

func TestCheckSeq(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()
	ok, known, err := c.CheckSeq(ctx, "dev1", 5, time.Hour)
	if err != nil || !ok || !known {
		t.Fatalf("first seq: %v %v %v", ok, known, err)
	}
	ok, _, _ = c.CheckSeq(ctx, "dev1", 5, time.Hour)
	if ok {
		t.Fatal("duplicate seq accepted")
	}
	ok, _, _ = c.CheckSeq(ctx, "dev1", 4, time.Hour)
	if ok {
		t.Fatal("regressed seq accepted")
	}
	ok, _, _ = c.CheckSeq(ctx, "dev1", 6, time.Hour)
	if !ok {
		t.Fatal("increased seq rejected")
	}
}

func TestRateLimit(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		ok, _, err := c.RateLimit(ctx, "ip:1.2.3.4", 3, 2*time.Second)
		if err != nil || !ok {
			t.Fatalf("req %d blocked: %v %v", i, ok, err)
		}
	}
	ok, _, _ := c.RateLimit(ctx, "ip:1.2.3.4", 3, 2*time.Second)
	if ok {
		t.Fatal("limit not enforced")
	}
	// 其他 key 不受影响
	ok, _, _ = c.RateLimit(ctx, "ip:5.6.7.8", 3, time.Minute)
	if !ok {
		t.Fatal("cross-key leak")
	}
	time.Sleep(2100 * time.Millisecond) // 窗口滑过
	ok, _, _ = c.RateLimit(ctx, "ip:1.2.3.4", 3, 2*time.Second)
	if !ok {
		t.Fatal("window not sliding")
	}
}

func TestRenewOnlineConcurrentLimit(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()
	// 上限 2 台并发
	if ok, _ := c.RenewOnline(ctx, "lic1", "devA", time.Minute, 2); !ok {
		t.Fatal("devA rejected")
	}
	if ok, _ := c.RenewOnline(ctx, "lic1", "devB", time.Minute, 2); !ok {
		t.Fatal("devB rejected")
	}
	if ok, _ := c.RenewOnline(ctx, "lic1", "devC", time.Minute, 2); ok {
		t.Fatal("devC admitted over limit")
	}
	// 自身续租不受名额影响
	if ok, _ := c.RenewOnline(ctx, "lic1", "devA", time.Minute, 2); !ok {
		t.Fatal("self renew rejected")
	}
	// 释放后可加入
	if err := c.DropOnline(ctx, "lic1", "devA"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.RenewOnline(ctx, "lic1", "devC", time.Minute, 2); !ok {
		t.Fatal("devC not admitted after release")
	}
	// TTL 过期后自动腾出名额（用真实短 TTL 验证 score 清理）
	if err := c.DropOnline(ctx, "lic1", "devB"); err != nil {
		t.Fatal(err)
	}
	if err := c.DropOnline(ctx, "lic1", "devC"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.RenewOnline(ctx, "lic1", "devX", 80*time.Millisecond, 2); !ok {
		t.Fatal("devX rejected")
	}
	if ok, _ := c.RenewOnline(ctx, "lic1", "devY", 80*time.Millisecond, 2); !ok {
		t.Fatal("devY rejected")
	}
	if ok, _ := c.RenewOnline(ctx, "lic1", "devZ", time.Minute, 2); ok {
		t.Fatal("devZ admitted over limit")
	}
	time.Sleep(120 * time.Millisecond)
	if ok, _ := c.RenewOnline(ctx, "lic1", "devZ", time.Minute, 2); !ok {
		t.Fatal("expired slot not reclaimed")
	}
}

func TestRateLimitConcurrent(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	admitted := make(chan struct{}, 100)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _, _ := c.RateLimit(ctx, "ip:burst", 10, time.Minute)
			if ok {
				admitted <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(admitted)
	n := 0
	for range admitted {
		n++
	}
	if n > 10 {
		t.Fatalf("race allowed %d over limit 10", n)
	}
}
