-- 自定义前缀为可选：批次前缀允许为空（0-8 位）。修复旧库中 length>=1 的检查约束，
-- 使"不填前缀直接制卡"在既有部署上同样可用；新库由 0001 直接建立正确约束。
DO $$
DECLARE
    current_def TEXT;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO current_def
    FROM pg_constraint
    WHERE conname = 'card_batches_prefix_check'
      AND conrelid = 'card_batches'::regclass;

    IF current_def IS NOT NULL AND current_def NOT LIKE '%BETWEEN 0 AND 8%' THEN
        ALTER TABLE card_batches DROP CONSTRAINT card_batches_prefix_check;
        ALTER TABLE card_batches
            ADD CONSTRAINT card_batches_prefix_check
            CHECK (length(prefix) BETWEEN 0 AND 8);
    END IF;
END $$;
