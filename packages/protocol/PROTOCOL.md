# 协议规范（v1）

所有接口仅在 HTTPS 上提供。客户端 SDK ↔ `/v1`；管理后台 ↔ `/admin/v1`（独立端口/域名）。

## 端点

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/v1/bootstrap` | 无 | KEX 公钥、签名公钥、服务器时间、策略参数 |
| POST | `/v1/activate` | 设备签名 | 激活（信封加密载荷） |
| POST | `/v1/heartbeat` | 设备签名 | 心跳续租，返回新租约 |
| POST | `/v1/redeem` | 设备签名 | 兑换续费卡（信封加密载荷） |
| POST | `/v1/deactivate` | 设备签名 | 自助解绑当前设备 |

## 设备签名（Proof-of-Possession）

请求头：

```
X-Vft-Device-Auth: v1 pub=<b64url> ts=<unix秒> nonce=<b64url 16B> seq=<单调递增> sig=<b64url>
```

签名覆盖串（`v1|METHOD|path|ts|nonce|seq|sha256(body)`）：

- Ed25519 设备密钥：对整条覆盖串直接签名。
- ECDSA P-256 设备密钥（SDK 默认，TPM 优先）：对 `sha256(覆盖串)` 签名；
  服务端接受 64 字节裸 `r||s`（Windows CNG）与 DER 两种编码。

服务端校验顺序：时间窗（±120s，可配）→ nonce 原子消费（重放窗口 5 分钟）→
序列号严格递增（Redis 先行、DB `last_seq` 兜底）→ 签名验证。

任一失败产生风险事件（replay / seq_regression / stale_timestamp）。

## 信封加密（激活/兑换载荷）

客户端构造载荷 JSON（卡密、指纹分量摘要、设备公钥、信任级、版本），然后：

1. `eph = X25519 临时密钥对`
2. `shared = X25519(eph.priv, serverKexPub)`
3. `key = HKDF-SHA256(shared, salt=epk_raw||spk_raw, info="vertify-envelope-v1")`
4. `ct = AES-256-GCM(key, nonce12B, payload, aad="vertify-envelope-v1|"+kid+"|A256GCM|purpose=<activate|redeem>")`

线上格式：

```json
{"kid":"kex-a","alg":"A256GCM","epk":"...","nonce":"...","ct":"..."}
```

AAD 绑定 `kid`/`alg`/`purpose`，跨接口重放密文无效。

## 指纹绑定

客户端上传若干**分量摘要**（每分量为规范化硬件标识的 SHA-256），
服务端以盐化合并计算 `fingerprint_hash = base64(sha256("vertify-fp-v1" || sha256(c1||c2||...) || fpSalt))`。
数据库不存原始序列号。绑定粒度 = 许可证 × 指纹；同指纹换密钥（重装系统）触发公钥轮换。

## 状态机

卡密：`unused → active → (frozen ⇄ active) / revoked / voided / depleted`（终态不可逆）。
许可证：`active / frozen / revoked / voided`。吊销/冻结在**一个心跳周期内**传播到在线客户端。

## 租约（VLT1 令牌）

```
VLT1.<b64url(payloadJSON)>.<b64url(Ed25519sig)>
```

- 签名覆盖**第二段 base64url 原始字节**（客户端无需重建 JSON，无序列化歧义）。
- 载荷：`typ/kid/jti/lic/prod/dev/feat/iat/exp/lex/pol/hbi/grace/st/mver`。
- TTL 默认 300s（套餐 `lease_ttl_seconds`）；心跳返回新租约。
- 客户端 `has_feature` 每次调用重新验签 + 有效期 + 设备绑定一致性检查，不缓存布尔值。

## 并发与名额语义

- **设备名额**（`device_limit`）：绑定门，激活时在 DB 事务中强制。
- **并发名额**（`concurrent_limit`）：在线门，心跳时经 Redis Lua 原子裁决
  （清理过期 → 自身续租放行 / 名额已满拒绝）。
- 激活时名额已满不阻断绑定；新设备首次心跳参与名额竞争。

## 错误码

`CARD_NOT_FOUND / CARD_INVALID / CARD_FROZEN / CARD_REVOKED / CARD_VOIDED / CARD_DEPLETED /
CARD_NOT_USABLE / LICENSE_FROZEN / LICENSE_REVOKED / LICENSE_VOIDED / LICENSE_EXPIRED /
DEVICE_LIMIT / CONCURRENT_LIMIT / DEVICE_NOT_FOUND / DEVICE_UNBOUND / REPLAY_DETECTED /
SEQ_REGRESSION / VERSION_TOO_OLD / RATE_LIMITED / BANNED / ENVELOPE_INVALID`

统一响应体 `{"error":{"code","message","request_id"}}`；文案泛化、不含内部细节。
