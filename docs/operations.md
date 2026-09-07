# 运维手册

## 架构

```
                    ┌─────────────┐
  客户端 SDK ──TLS──▶│ Ingress/WAF │──▶ vertify-api ×N（无状态）
  管理后台  ──TLS──▶ │  （分域）   │      │        │
                    └─────────────┘      ▼        ▼
                                   PostgreSQL HA   Redis HA
                                   （事实来源）    （在线状态/nonce/限流）
                                          │
                                          └── 迁移 Job（部署前执行）
```

- API 多副本 + 跨可用区反亲和；HPA 按 CPU 65% 扩容（3–12 副本）。
- PostgreSQL：托管 HA、PITR、只读副本（报表查询）。
- Redis：HA/Cluster；故障时 API 降级放行（限流/nonce 退化为 DB 序列号兜底），并产生告警。

## 部署

```bash
# 迁移 Job（ArgoCD PreSync 或流水线步骤）
helm upgrade vertify deploy/helm/vertify --install

# 数据库迁移绝不随 API Pod 并发执行
kubectl -n vertify create job --from=job/vertify-migrate vertify-migrate-$(date +%s)
```

## SLO 与告警

| 指标 | 目标 | 告警 |
|---|---|---|
| `/v1/*` 可用性 | ≥ 99.9% | 5 分钟错误率 > 1% |
| 激活 P95 延迟 | ≤ 200ms | 15 分钟 P95 > 500ms |
| 心跳 P95 延迟 | ≤ 50ms | 15 分钟 P95 > 150ms |
| 吊销传播时间 | ≤ 1 心跳周期 | — |
| Redis 错误 | 0 | 1 分钟内 > 10 次（降级告警） |
| 风险事件速率 | 基线 | 5 分钟内 replay 类 > 100（攻击告警） |

## 常见操作

### 卡密应急响应（疑似泄露）
1. 管理面按前缀检索 → 卡密吊销（级联许可证）。
2. 在线客户端在一个心跳周期内收到 `LICENSE_REVOKED`。
3. 审计日志核对操作链；风险事件面板确认异常来源。

### 密钥轮换
1. `cmd/keygen` 生成新 kid → 加入 `VFT_SIGN_KEYS`（新旧并存）→ `VFT_SIGN_ACTIVE_KID` 指向新 kid → 滚动重启。
2. 观察 `兼容率`（老客户端用旧 kid 验签仍通过）≥ 99.9% 后移除旧 kid。

### 数据库故障切换
- 托管 HA 自动切换；API 连接池自动重连。
- 切换期间激活/心跳失败：客户端指数退避，租约未过期不中断业务。

### 备份与恢复
- PostgreSQL 每日全量 + WAL 归档（RPO ≤ 5 分钟）；每季度恢复演练。
- 恢复后：KMS 密钥不变（卡密 HMAC/签名验签连续）；Redis 冷启动无影响（nonce 窗口短）。

## 容量参考

- 单副本 2C4G：激活 ~200 QPS、心跳 ~5000 QPS（瓶颈在 PG 写入）。
- 心跳为主负载：3 副本 + 心跳间隔 60s 可支撑 ~90 万在线设备。
- **连接数预算**：副本数 × `VFT_DB_MAX_CONNS`（默认 20）+ 运维连接 ≤ PG `max_connections`；
  12 副本 × 20 = 240 > 默认 100，扩容时须同步上调 PG `max_connections` 或下调每副本连接数。

## 降级语义（必须知晓）

- **Redis 不可用时**：限流与 nonce 防重放退化为「序列号 DB 兜底 + 时间窗」，
  激活接口的nonce 检查跳过（由时间窗与幂等事务兜底）。此期间应触发告警并尽快恢复 Redis。
- **KMS 不可用时**：签名操作失败，激活与心跳全部失败（拒绝服务优于签发无效凭据）。
- **管理员登录双轨限速**：IP 10 次/分钟 + 账户 5 次失败锁 15 分钟。
- **mfa_required 响应**：正确口令 + 未提供 TOTP 返回 200/`mfa_required`，与错误口令的 401
  可区分——属两步登录的固有语义（业界通行），已在威胁模型中记录为接受的风险。
