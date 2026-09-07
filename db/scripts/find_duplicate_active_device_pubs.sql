-- 查询活动设备公钥重复项；清理前请先备份数据库并逐组确认保留设备。
SELECT device_pub, COUNT(*) AS active_count,
       string_agg(id::text, ',' ORDER BY bound_at DESC) AS device_ids
FROM devices
WHERE status = 'active'
GROUP BY device_pub
HAVING COUNT(*) > 1
ORDER BY active_count DESC;
