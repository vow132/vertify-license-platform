-- 0006_card_secret.sql: encrypted recoverable card secret and soft deletion
ALTER TABLE cards ADD COLUMN IF NOT EXISTS secret_ciphertext BYTEA;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS secret_nonce BYTEA;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS secret_key_version TEXT;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS deleted_by UUID;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS delete_reason TEXT;
ALTER TABLE cards ADD CONSTRAINT cards_secret_complete CHECK (
  (secret_ciphertext IS NULL AND secret_nonce IS NULL AND secret_key_version IS NULL)
  OR (secret_ciphertext IS NOT NULL AND secret_nonce IS NOT NULL AND secret_key_version IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_cards_deleted_at ON cards(deleted_at);
