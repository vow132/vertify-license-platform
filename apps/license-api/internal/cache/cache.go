// Package cache 封装 Redis 上的在线状态与安全原语：
// nonce 防重放、设备序列号、滑动窗口限流、并发在线租约。
// 所有关键操作使用 Lua 脚本保证原子性；数据库仍是授权事实来源。
package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vertify/license-platform/internal/crypto"
)

type Cache struct {
	rdb *redis.Client
}

func New(ctx context.Context, redisURL string) (*Cache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("cache: parse url: %w", err)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("cache: ping: %w", err)
	}
	return &Cache{rdb: rdb}, nil
}

func (c *Cache) Close() error { return c.rdb.Close() }

func (c *Cache) Ping(ctx context.Context) error { return c.rdb.Ping(ctx).Err() }

// FlushDB 清空当前逻辑库（测试隔离用）。
func (c *Cache) FlushDB(ctx context.Context) error { return c.rdb.FlushDB(ctx).Err() }

// ConsumeNonce 原子消费一次 nonce：首次返回 true，重复返回 false。
// scope 区分用途（activate/heartbeat/redeem），TTL 必须覆盖请求时间戳容差窗口。
func (c *Cache) ConsumeNonce(ctx context.Context, scope, nonce string, ttl time.Duration) (bool, error) {
	key := fmt.Sprintf("nonce:%s:%s", scope, nonce)
	ok, err := c.rdb.SetNX(ctx, key, 1, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("cache: nonce: %w", err)
	}
	return ok, nil
}

// seqScript：序列号单调递增校验。返回 1=接受，0=倒退/重复。
var seqScript = redis.NewScript(`
local cur = tonumber(redis.call("GET", KEYS[1]) or "-1")
local seq = tonumber(ARGV[1])
if seq <= cur then
  return 0
end
redis.call("SET", KEYS[1], tostring(seq), "PX", ARGV[2])
return 1
`)

// CheckSeq 校验设备序列号严格递增。Redis 丢失（重启/切换）时返回 ok=true 并由
// 调用方回查数据库 last_seq 作为最终事实。
func (c *Cache) CheckSeq(ctx context.Context, deviceID string, seq int64, ttl time.Duration) (ok bool, known bool, err error) {
	res, err := seqScript.Run(ctx, c.rdb, []string{"seq:dev:" + deviceID}, seq, ttl.Milliseconds()).Int()
	if err != nil {
		return false, false, fmt.Errorf("cache: seq: %w", err)
	}
	return res == 1, true, nil
}

// RateLimit sliding-window：key 在 window 内最多 limit 次。
var rlScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call("ZREMRANGEBYSCORE", key, 0, now - window)
local n = redis.call("ZCARD", key)
if n >= limit then
  return 0
end
redis.call("ZADD", key, now, member)
redis.call("PEXPIRE", key, window)
return limit - n
`)

// RateLimit 返回 (allowed, remaining, err)。member 必须唯一，防止同毫秒 ZADD 覆盖。
func (c *Cache) RateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	now := time.Now().UnixMilli()
	member, err := crypto.RandomToken(8)
	if err != nil {
		return false, 0, err
	}
	res, err := rlScript.Run(ctx, c.rdb, []string{"rl:" + key}, now, window.Milliseconds(), limit, member).Int()
	if err != nil {
		return false, 0, fmt.Errorf("cache: ratelimit: %w", err)
	}
	if res == 0 {
		return false, 0, nil
	}
	return true, res, nil
}

// onlineScript：并发在线名额原子控制。
// KEYS[1]=zset key; ARGV: now_ms, ttl_ms, device_id, limit
// 返回: 1=续租成功（名额内），0=名额已满，2=自身已在（续租）
var onlineScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local dev = ARGV[3]
local limit = tonumber(ARGV[4])
redis.call("ZREMRANGEBYSCORE", key, 0, now)
local score = redis.call("ZSCORE", key, dev)
if score then
  redis.call("ZADD", key, now + ttl, dev)
  return 2
end
local n = redis.call("ZCARD", key)
if n >= limit then
  return 0
end
redis.call("ZADD", key, now + ttl, dev)
return 1
`)

// RenewOnline 续租设备在线状态并强制并发上限。返回 (admitted, err)。
func (c *Cache) RenewOnline(ctx context.Context, licenseID, deviceID string, ttl time.Duration, concurrentLimit int) (bool, error) {
	now := time.Now().UnixMilli()
	res, err := onlineScript.Run(ctx, c.rdb,
		[]string{"online:lic:" + licenseID},
		now, ttl.Milliseconds(), deviceID, concurrentLimit).Int()
	if err != nil {
		return false, fmt.Errorf("cache: online: %w", err)
	}
	return res == 1 || res == 2, nil
}

// DropOnline 设备主动下线/解绑时移除在线名额。
func (c *Cache) DropOnline(ctx context.Context, licenseID, deviceID string) error {
	return c.rdb.ZRem(ctx, "online:lic:"+licenseID, deviceID).Err()
}

// OnlineCount 返回当前在线设备数。
func (c *Cache) OnlineCount(ctx context.Context, licenseID string) (int64, error) {
	return c.rdb.ZCard(ctx, "online:lic:"+licenseID).Result()
}

// OnlineDevices 返回在线设备 ID 列表（清理过期后）。
func (c *Cache) OnlineDevices(ctx context.Context, licenseID string) ([]string, error) {
	now := time.Now().UnixMilli()
	key := "online:lic:" + licenseID
	if err := c.rdb.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", now)).Err(); err != nil {
		return nil, err
	}
	return c.rdb.ZRange(ctx, key, 0, -1).Result()
}

// IncrWindow 窗口内自增计数（枚举检测）。返回当前计数。
var incrScript = redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
if n == 1 then
  redis.call("PEXPIRE", KEYS[1], tonumber(ARGV[1]))
end
return n
`)

func (c *Cache) Incr(ctx context.Context, key string, windowSeconds int) (int64, error) {
	return incrScript.Run(ctx, c.rdb, []string{"cnt:" + key}, windowSeconds*1000).Int64()
}

// CacheGet / CacheSet 通用短缓存（bootstrap 快照等）。
func (c *Cache) CacheGet(ctx context.Context, key string) (string, bool, error) {
	v, err := c.rdb.Get(ctx, "k:"+key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (c *Cache) CacheSet(ctx context.Context, key, val string, ttl time.Duration) error {
	return c.rdb.Set(ctx, "k:"+key, val, ttl).Err()
}

func (c *Cache) SetPendingTOTP(ctx context.Context, adminID, secret string, ttl time.Duration) error {
	return c.rdb.Set(ctx, "mfa:pending:"+adminID, secret, ttl).Err()
}

func (c *Cache) ConsumePendingTOTP(ctx context.Context, adminID string) (string, error) {
	key := "mfa:pending:" + adminID
	v, err := c.rdb.GetDel(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", fmt.Errorf("pending mfa setup not found")
	}
	return v, err
}

func (c *Cache) ConsumeTOTPWindow(ctx context.Context, adminID string, step int64, ttl time.Duration) (bool, error) {
	return c.rdb.SetNX(ctx, fmt.Sprintf("mfa:used:%s:%d", adminID, step), 1, ttl).Result()
}
