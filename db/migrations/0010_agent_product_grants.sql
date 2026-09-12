-- 代理商产品授权：只有被开通的产品，代理商才能制卡和查看。
-- 未开通的产品对代理商不可见，制卡请求会被拒绝。
CREATE TABLE IF NOT EXISTS agent_product_grants (
    agent_id   UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, product_id)
);
