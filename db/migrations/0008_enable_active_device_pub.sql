-- 启用活动设备公钥唯一性。历史重复数据存在时先保留服务可启动，
-- 并由运维脚本清理后再次执行索引创建；服务层同时拒绝新的冲突轮换。
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM devices
        WHERE status = 'active'
        GROUP BY device_pub
        HAVING COUNT(*) > 1
    ) THEN
        CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_active_pub
            ON devices(device_pub)
            WHERE status = 'active';
    ELSE
        RAISE NOTICE 'uq_devices_active_pub deferred: duplicate active device_pub rows exist';
    END IF;
END $$;
