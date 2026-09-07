-- 0004_user_accounts.sql — 终端用户账号体系 + 公告/版本 + 接口限流配置
-- 账号制与既有"卡密激活制"并存：卡密既能开许可证（激活制），也能给账号续期（账号制），
-- 同一张卡只能被其中一种方式消耗（cards.used_by_user / cards.license_id 互斥消耗）。

-- ===== 终端用户账号（每产品独立命名空间） =====
CREATE TABLE end_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id      UUID NOT NULL REFERENCES products(id),
    username        TEXT NOT NULL CHECK (username ~ '^[a-zA-Z0-9_]{3,32}$'),
    password_hash   TEXT NOT NULL,                 -- argon2id
    security_hash   TEXT NOT NULL,                 -- 安全码 argon2id（找回密码）
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT now(),  -- 绑卡续期；默认即刻到期（需绑卡）
    machine_hash    TEXT,                          -- 首次登录绑定的机器指纹摘要
    machine_bound_at TIMESTAMPTZ,
    reg_ip          INET,
    last_login_at   TIMESTAMPTZ,
    last_ip         INET,
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (product_id, username)
);
CREATE INDEX idx_end_users_product ON end_users(product_id, status);

-- ===== 用户日志（登录/注册/绑卡/改密/找回，追加写） =====
CREATE TABLE end_user_logs (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID REFERENCES end_users(id),
    username   TEXT NOT NULL,
    product_id UUID,
    kind       TEXT NOT NULL CHECK (kind IN (
        'register','login','login_failed','login_machine_rejected',
        'bind_card','change_pw','recover','disabled','machine_reset')),
    ip         INET,
    detail     JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_user_logs_user ON end_user_logs(user_id, created_at DESC);
CREATE INDEX idx_user_logs_time ON end_user_logs(created_at DESC);

-- ===== 卡密增加账号消耗标记 =====
ALTER TABLE cards ADD COLUMN used_by_user UUID REFERENCES end_users(id);

-- ===== 软件公告（客户端登录/心跳时下发） =====
CREATE TABLE soft_messages (
    id         BIGSERIAL PRIMARY KEY,
    product_id UUID NOT NULL REFERENCES products(id),
    content    TEXT NOT NULL CHECK (length(content) BETWEEN 1 AND 2000),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_soft_msg ON soft_messages(product_id, enabled, created_at DESC);

-- ===== 软件版本（取版本/下载/强制更新） =====
CREATE TABLE product_versions (
    id            BIGSERIAL PRIMARY KEY,
    product_id    UUID NOT NULL REFERENCES products(id),
    version       TEXT NOT NULL CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    download_url  TEXT NOT NULL,
    notes         TEXT,
    force_update  BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (product_id, version)
);
CREATE INDEX idx_product_ver ON product_versions(product_id, created_at DESC);

-- ===== 接口级限流配置（后台可调：xx 分钟内 xx 次） =====
CREATE TABLE api_rate_limits (
    scope          TEXT PRIMARY KEY,   -- activate | heartbeat | user_login | user_register | bootstrap | redeem
    limit_per_min  INT NOT NULL CHECK (limit_per_min BETWEEN 1 AND 100000),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
