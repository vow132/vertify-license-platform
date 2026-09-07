# 开发环境

## 方式一：Docker Compose（推荐）

```bash
cp .env.example .env            # 填入 keygen 生成的密钥
docker compose -f deploy/compose/docker-compose.yml up --build
```

## 方式二：本机直跑（Windows）

依赖：Go 1.27+、PostgreSQL 16、Redis 7。

```bash
# 生成开发密钥（仅开发环境！）
cd apps/license-api && go run ./cmd/keygen > dev.env

# 数据库迁移 + 初始管理员
go run ./cmd/migrate up
set VFT_INITIAL_ADMIN_USER=admin
set VFT_INITIAL_ADMIN_PASSWORD=<dev密码>
go run ./cmd/server          # 客户端 :8080 / 管理 :8081 / 指标 :9090

# 本地 TLS（SDK 联调用）
go run ./cmd/tlscert ../../.tools/tls
set VFT_TLS_CERT=../../.tools/tls/cert.pem
set VFT_TLS_KEY=../../.tools/tls/key.pem
```

管理后台：`cd apps/admin-web && npm ci && npm run dev`（5173，代理 /admin → 8081）。

## 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `VFT_SIGN_KEYS` | ✓ | Ed25519 签名密钥 `kid:seedB64,...` |
| `VFT_SIGN_ACTIVE_KID` | ✓ | 当前签名 kid |
| `VFT_KEX_KEYS` | ✓ | 信封加密 X25519 私钥 `kid:seedB64[*],...`（* 为 active） |
| `VFT_CARD_HMAC_KEY` | ✓ | 卡密 HMAC 主密钥（≥32B base64url） |
| `VFT_DATABASE_URL` | ✓ | PostgreSQL DSN |
| `VFT_REDIS_URL` | ✓ | Redis DSN |
| `VFT_INITIAL_ADMIN_USER/PASSWORD` | 首启 | 空表时创建初始管理员 |
| `VFT_TRUSTED_PROXIES` | 生产 | 可信代理 CIDR（采信 X-Forwarded-For） |
| `VFT_TLS_CERT/KEY` | 可选 | 客户端面 TLS（生产建议网关终结） |
| `VFT_ACTIVATE_RPM` 等 | 可选 | 客户端限流阈值 |
| `VFT_ADMIN_LOGIN_RPM` | 可选 | 管理面登录 IP 限流（默认 10） |
| `VFT_DB_MAX_CONNS` | 可选 | 每副本 PG 连接数（默认 20；多副本按 max_connections 预算） |
| `VFT_DEBUG=1` | 调试 | 服务端/SDK 输出调试信息 |

## 测试

```bash
cd apps/license-api
go test ./... -race                        # 单元
go test -tags integration ./internal/integration/ -v   # E2E（需 PG+Redis）
```

E2E 覆盖：制卡→激活→心跳→冻结→解绑→重绑→续费→吊销级联，以及
重放/序列号倒退/篡改/伪造/跨用途重放/CSRF/未认证/信息泄漏等安全负向用例。
