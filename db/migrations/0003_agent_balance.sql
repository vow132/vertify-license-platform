-- 0003_agent_balance.sql — 代理余额体系
-- 余额以"分"存储（整数），避免浮点误差；UI 按 元=分/100 展示。
-- 总经销给套餐定价（price_cents），代理制卡时按 数量×单价 扣余额。

ALTER TABLE agents ADD COLUMN balance_cents BIGINT NOT NULL DEFAULT 0
    CHECK (balance_cents >= 0);
ALTER TABLE plans ADD COLUMN price_cents BIGINT NOT NULL DEFAULT 0
    CHECK (price_cents >= 0);

-- 代理资金流水（追加写）：充值/调差/制卡扣款
CREATE TABLE agent_transactions (
    id             BIGSERIAL PRIMARY KEY,
    agent_id       UUID NOT NULL REFERENCES agents(id),
    amount_cents   BIGINT NOT NULL,            -- 正=入账，负=扣款
    balance_after  BIGINT NOT NULL,            -- 交易后余额（对账用）
    kind           TEXT NOT NULL CHECK (kind IN ('topup','adjust','batch_purchase')),
    ref_batch_id   UUID,
    note           TEXT,
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_tx ON agent_transactions(agent_id, created_at DESC);
