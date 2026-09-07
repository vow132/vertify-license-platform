import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { get, post } from '../api'
import { Badge, fmtTime } from '../components'
import { usePermissions } from '../auth'

interface License {
  id: string
  product_id: string
  plan_id: string
  status: string
  activated_at: string
  expires_at: string | null
  policy_version: number
  note: string | null
}
interface Device {
  id: string
  status: string
  trust_level: string
  device_pub: string
  bound_at: string
  last_heartbeat_at: string | null
  last_ip: string | null
  client_version: string | null
}
interface Event {
  id: number
  kind: string
  actor: string
  detail: { info?: Record<string, unknown>; text?: string }
  created_at: string
}

export default function LicenseDetail() {
  const { id } = useParams()
  const [data, setData] = useState<{ license: License; devices: Device[]; events: Event[]; online: string[] } | null>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const permissions = usePermissions()
  const canManage = permissions.includes('licenses:manage')
  const canUnbind = permissions.includes('devices:manage')

  const load = useCallback(async () => {
    setLoading(true); setErr('')
    try { const r = await get<{ license: License; devices: Device[]; events: Event[]; online: string[] }>(`/admin/v1/licenses/${id}`); setData(r) }
    catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
  }, [id])
  useEffect(() => { void load() }, [load])

  if (loading) return <div className="panel muted">加载中…</div>
  if (err) return <div className="panel error-text">{err}<button className="ghost small" onClick={() => void load()}>重试</button></div>
  if (!data) return <div className="panel muted">暂无许可证数据</div>
  const { license, devices, events, online } = data

  const act = async (action: string) => {
    const label = action === 'freeze' ? '冻结' : action === 'revoke' ? '吊销' : action === 'void' ? '作废' : '解冻'
    const reason = prompt(`请输入${label}原因（将写入审计日志）：`)
    if (!reason) return
    setBusy(true)
    try { await post(`/admin/v1/licenses/${license.id}/action`, { action, reason }); await load() }
    catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const unbind = async (deviceId: string) => {
    const reason = prompt('请输入解绑原因：')
    if (!reason) return
    setBusy(true)
    try { await post(`/admin/v1/devices/${deviceId}/unbind`, { reason }); await load() }
    catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const note = async () => {
    const n = prompt('备注内容：', license.note || '')
    if (n === null) return
    setBusy(true)
    try { await post(`/admin/v1/licenses/${license.id}/note`, { note: n }); await load() }
    catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }

  return (
    <>
      <h2 className="page-title">许可证 {license.id.slice(0, 8)}… <Badge status={license.status} /></h2>
      <div className="panel">
        <div className="toolbar">
          {canManage && license.status === 'active' && <button className="warn" disabled={busy} onClick={() => void act('freeze')}>冻结</button>}
          {canManage && license.status === 'frozen' && <button disabled={busy} onClick={() => void act('unfreeze')}>解冻</button>}
          {canManage && (license.status === 'active' || license.status === 'frozen') && (
            <>
              <button className="danger" disabled={busy} onClick={() => void act('revoke')}>吊销</button>
              <button className="danger" disabled={busy} onClick={() => void act('void')}>作废</button>
            </>
          )}
          {canManage && <button className="ghost" disabled={busy} onClick={async () => {
            const days = prompt('手动续期天数：')
            if (!days || !Number.isInteger(Number(days)) || Number(days) <= 0 || Number(days) > 36500) return
            const reason = prompt('续期原因（写审计）：') || ''
            if (!reason) return
            setBusy(true)
            try { await post(`/admin/v1/licenses/${license.id}/extend`, { days: Number(days), reason }); await load() }
            catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
          }}>手动续期</button>}
          {canManage && <button className="ghost" disabled={busy} onClick={() => void note()}>编辑备注</button>}
          <button className="ghost" onClick={load}>刷新</button>
        </div>
        <div className="kv">
          <div className="k">许可证 ID</div><div className="mono">{license.id}</div>
          <div className="k">激活时间</div><div>{fmtTime(license.activated_at)}</div>
          <div className="k">到期时间</div><div>{license.expires_at ? fmtTime(license.expires_at) : '永久'}</div>
          <div className="k">策略版本</div><div className="mono">v{license.policy_version}</div>
          <div className="k">当前在线</div><div>{online.length} 台</div>
          <div className="k">备注</div><div>{license.note || '—'}</div>
        </div>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>绑定设备</h3>
        <table>
          <thead>
            <tr><th>设备 ID</th><th>状态</th><th>信任级</th><th>绑定时间</th><th>最近心跳</th><th>IP</th><th>版本</th><th>操作</th></tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id}>
                <td className="mono">{d.id.slice(0, 8)}…</td>
                <td><Badge status={d.status} /></td>
                <td>{d.trust_level === 'tpm' ? 'TPM 硬件' : '软件'}</td>
                <td className="muted">{fmtTime(d.bound_at)}</td>
                <td className="muted">{fmtTime(d.last_heartbeat_at)}</td>
                <td className="mono">{d.last_ip || '—'}</td>
                <td className="mono">{d.client_version || '—'}</td>
                <td>
                  {canUnbind && d.status === 'active' && (
                    <button className="warn small" disabled={busy} onClick={() => void unbind(d.id)}>解绑</button>
                  )}
                </td>
              </tr>
            ))}
            {devices.length === 0 && <tr><td colSpan={8} className="muted">无设备</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>事件历史</h3>
        <table>
          <thead><tr><th>时间</th><th>事件</th><th>操作者</th><th>详情</th></tr></thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id}>
                <td className="muted">{fmtTime(ev.created_at)}</td>
                <td><Badge status={ev.kind} /></td>
                <td className="mono">{ev.actor}</td>
                <td className="muted mono" style={{ maxWidth: 420, wordBreak: 'break-all' }}>
                  {JSON.stringify(ev.detail?.info ?? ev.detail ?? {})}
                </td>
              </tr>
            ))}
            {events.length === 0 && <tr><td colSpan={4} className="muted">无事件</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  )
}
