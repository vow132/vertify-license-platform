-- 0001_init.sql — Vertify 许可平台初始 Schema
-- 状态机以 CHECK 约束固化；授权事实来源是 PostgreSQL。

-- ===== 渠道 / 代理商 =====
CREATE TABLE agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    parent_id   UUID REFERENCES agents(id),
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 产品 =====
CREATE TABLE products (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        TEXT NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9_]{2,32}$'),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 套餐（授权策略） =====
CREATE TABLE plans (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id                UUID NOT NULL REFERENCES products(id),
    code                      TEXT NOT NULL UNIQUE CHECK (code ~ '^[a-z0-9_-]{2,64}$'),
    name                      TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    kind                      TEXT NOT NULL DEFAULT 'duration' CHECK (kind IN ('duration','fixed','permanent','uses')),
    duration_days             INT  NOT NULL DEFAULT 0 CHECK (duration_days >= 0 AND duration_days <= 36500),
    fixed_expiry_days         INT  NOT NULL DEFAULT 0 CHECK (fixed_expiry_days >= 0),
    uses_total                INT  NOT NULL DEFAULT 0 CHECK (uses_total >= 0),
    device_limit              INT  NOT NULL CHECK (device_limit BETWEEN 1 AND 100),
    concurrent_limit          INT  NOT NULL CHECK (concurrent_limit BETWEEN 1 AND 100),
    features                  JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(features) = 'array'),
    offline_grace_seconds     INT  NOT NULL DEFAULT 0 CHECK (offline_grace_seconds BETWEEN 0 AND 604800),
    lease_ttl_seconds         INT  NOT NULL DEFAULT 300 CHECK (lease_ttl_seconds BETWEEN 60 AND 86400),
    heartbeat_interval_seconds INT NOT NULL DEFAULT 60 CHECK (heartbeat_interval_seconds BETWEEN 10 AND 3600),
    rebind_cooldown_hours     INT  NOT NULL DEFAULT 24 CHECK (rebind_cooldown_hours >= 0),
    monthly_rebind_limit      INT  NOT NULL DEFAULT 2 CHECK (monthly_rebind_limit >= 0),
    min_client_version        TEXT NOT NULL DEFAULT '',
    status                    TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_plans_product ON plans(product_id);

-- ===== 卡密批次 =====
CREATE TABLE card_batches (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID REFERENCES agents(id),
    product_id  UUID NOT NULL REFERENCES products(id),
    plan_id     UUID NOT NULL REFERENCES plans(id),
    quantity    INT NOT NULL CHECK (quantity BETWEEN 1 AND 100000),
    prefix      TEXT NOT NULL CHECK (length(prefix) BETWEEN 1 AND 8),
    note        TEXT,
    created_by  UUID NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_batches_created ON card_batches(created_at DESC);

-- ===== 卡密（不存明文：lookup=HMAC-SHA256 hex，prefix=首组） =====
CREATE TABLE cards (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id     UUID NOT NULL REFERENCES card_batches(id),
    agent_id     UUID REFERENCES agents(id),
    product_id   UUID NOT NULL REFERENCES products(id),
    plan_id      UUID NOT NULL REFERENCES plans(id),
    lookup       CHAR(64) NOT NULL UNIQUE,   -- HMAC-SHA256(normalized card)
    prefix       TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'license' CHECK (kind IN ('license','renewal')),
    status       TEXT NOT NULL DEFAULT 'unused'
                 CHECK (status IN ('unused','active','frozen','revoked','voided','depleted')),
    uses_total   INT  NOT NULL DEFAULT 0,
    uses_left    INT  NOT NULL DEFAULT 0,
    license_id   UUID,                        -- kind=license 激活后指向
    activated_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,                 -- kind=fixed 的固定有效期
    created_by   UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 状态机（终态不可转出）
    CONSTRAINT cards_state CHECK (
        (status = 'unused') OR
        (status = 'active' AND activated_at IS NOT NULL) OR
        (status IN ('frozen','revoked','voided','depleted'))
    )
);
CREATE INDEX idx_cards_prefix ON cards(prefix);
CREATE INDEX idx_cards_batch ON cards(batch_id);
CREATE INDEX idx_cards_status ON cards(status);
CREATE INDEX idx_cards_agent ON cards(agent_id);

-- ===== 许可证 =====
CREATE TABLE licenses (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id     UUID NOT NULL REFERENCES products(id),
    plan_id        UUID NOT NULL REFERENCES plans(id),
    agent_id       UUID REFERENCES agents(id),
    origin_card_id UUID NOT NULL REFERENCES cards(id),
    status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','frozen','revoked','voided')),
    uses_left      INT,
    activated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ,               -- NULL = 永久
    policy_version BIGINT NOT NULL DEFAULT 1,
    note           TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_licenses_status ON licenses(status);
CREATE INDEX idx_licenses_agent ON licenses(agent_id);

-- ===== 设备（机器码绑定） =====
CREATE TABLE devices (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id        UUID NOT NULL REFERENCES licenses(id),
    fingerprint_hash  TEXT NOT NULL,            -- 服务端盐化指纹摘要 hex
    device_pub        TEXT NOT NULL,            -- base64url Ed25519 公钥（32B）
    trust_level       TEXT NOT NULL DEFAULT 'software' CHECK (trust_level IN ('tpm','software')),
    hw_snapshot       JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(hw_snapshot) = 'object'),
    status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','unbound')),
    bound_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    unbound_at        TIMESTAMPTZ,
    unbound_by        TEXT,
    last_heartbeat_at TIMESTAMPTZ,
    last_ip           INET,
    client_version    TEXT,
    last_seq          BIGINT NOT NULL DEFAULT 0, -- 防重放最终事实
    UNIQUE (license_id, fingerprint_hash)
);
CREATE INDEX idx_devices_license ON devices(license_id) WHERE status = 'active';
CREATE INDEX idx_devices_pub ON devices(device_pub);

-- ===== 激活记录 =====
CREATE TABLE activations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id  UUID NOT NULL REFERENCES licenses(id),
    card_id     UUID NOT NULL REFERENCES cards(id),
    device_id   UUID NOT NULL REFERENCES devices(id),
    kind        TEXT NOT NULL CHECK (kind IN ('initial','rebind','reactivation')),
    ip          INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_activations_lic ON activations(license_id, created_at DESC);

-- ===== 续费记录 =====
CREATE TABLE renewals (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id     UUID NOT NULL REFERENCES licenses(id),
    card_id        UUID NOT NULL REFERENCES cards(id),
    days_added     INT NOT NULL CHECK (days_added > 0),
    old_expires_at TIMESTAMPTZ,
    new_expires_at TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_renewals_lic ON renewals(license_id, created_at DESC);

-- ===== 许可事件（追加写，不可变） =====
CREATE TABLE license_events (
    id          BIGSERIAL PRIMARY KEY,
    license_id  UUID NOT NULL REFERENCES licenses(id),
    kind        TEXT NOT NULL CHECK (kind IN (
        'activated','renewed','frozen','unfrozen','revoked','voided',
        'device_bound','device_unbound','expired','policy_updated')),
    actor       TEXT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}',
    request_id  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_license_events_lic ON license_events(license_id, created_at DESC);

-- ===== 后台管理员 =====
CREATE TABLE admins (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username            TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-zA-Z0-9_.-]{3,64}$'),
    password_hash       TEXT NOT NULL,        -- argon2id PHC
    display_name        TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN ('superadmin','admin','agent','auditor','viewer')),
    agent_id            UUID REFERENCES agents(id),  -- agent 角色数据范围
    totp_secret         TEXT,                 -- base32；启用 MFA 后非空
    mfa_enabled         BOOLEAN NOT NULL DEFAULT false,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    failed_attempts     INT NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    must_change_password BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at       TIMESTAMPTZ
);

-- ===== 后台会话（cookie 存随机 token；库存其 SHA-256） =====
CREATE TABLE admin_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id    UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    token_hash  CHAR(64) NOT NULL UNIQUE,
    csrf_token  TEXT NOT NULL,
    mfa_passed  BOOLEAN NOT NULL DEFAULT false,
    ip          INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX idx_sessions_admin ON admin_sessions(admin_id);

-- ===== 审计日志（追加写） =====
CREATE TABLE audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
    admin_id      UUID,
    admin_username TEXT,
    action        TEXT NOT NULL,
    target_type   TEXT,
    target_id     TEXT,
    before_state  JSONB,
    after_state   JSONB,
    detail        JSONB NOT NULL DEFAULT '{}',
    ip            INET,
    request_id    TEXT
);
CREATE INDEX idx_audit_ts ON audit_logs(ts DESC);
CREATE INDEX idx_audit_admin ON audit_logs(admin_id, ts DESC);
CREATE INDEX idx_audit_action ON audit_logs(action, ts DESC);

-- ===== 风险事件 =====
CREATE TABLE risk_events (
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind      TEXT NOT NULL,
    severity  TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
    subject   TEXT,
    detail    JSONB NOT NULL DEFAULT '{}',
    action    TEXT NOT NULL DEFAULT 'logged' CHECK (action IN ('logged','throttled','blocked','banned'))
);
CREATE INDEX idx_risk_ts ON risk_events(ts DESC);
CREATE INDEX idx_risk_kind ON risk_events(kind, ts DESC);

-- ===== 封禁 =====
CREATE TABLE bans (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       TEXT NOT NULL CHECK (kind IN ('ip','device','card_prefix','client_version','asn')),
    value      TEXT NOT NULL,
    reason     TEXT,
    until      TIMESTAMPTZ,                    -- NULL = 永久
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);

-- ===== 信封加密 KEX 公钥登记（私钥在 KMS/Secret，此处仅供 bootstrap 下发与审计） =====
CREATE TABLE kex_keys (
    kid        TEXT PRIMARY KEY,
    pub        TEXT NOT NULL,
    alg        TEXT NOT NULL DEFAULT 'A256GCM',
    active     BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO agents (name) VALUES ('直营') RETURNING id;
