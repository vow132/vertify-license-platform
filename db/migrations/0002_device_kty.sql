-- 0002_device_kty.sql — 设备公钥类型（支持 TPM/BCrypt ECDSA P-256 与软件 Ed25519 双轨）
ALTER TABLE devices ADD COLUMN pub_kty TEXT NOT NULL DEFAULT 'ed25519'
    CHECK (pub_kty IN ('ed25519','p256'));
