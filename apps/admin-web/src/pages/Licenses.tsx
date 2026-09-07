import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { get, post, qs } from '../api'
import { Badge, Pager, fmtTime } from '../components'
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

export default function Licenses() {
  const [items, setItems] = useState<License[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [f, setF] = useState({ status: '', q: '' })
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const permissions = usePermissions()
  const canManage = permissions.includes('licenses:manage')

  const load = useCallback(async () => {
    setLoading(true); setErr('')
    try { const r = await get<{ items: License[]; total: number }>(`/admin/v1/licenses${qs({ ...f, limit: 50, offset })}`); setItems(r.items); setTotal(r.total) }
    catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
  }, [f, offset])
  useEffect(() => { void load() }, [load])

  const act = async (id: string, action: string) => {
    const label = action === 'freeze' ? '冻结' : action === 'revoke' ? '吊销' : '作废'
    const reason = prompt(`请输入${label}原因（将写入审计日志）：`)
    if (!reason) return
    setBusy(true)
    try { await post(`/admin/v1/licenses/${id}/action`, { action, reason }); await load() }
    catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }

  return (
    <>
      <h2 className="page-title">已激活授权</h2>
      <div className="panel intro-panel"><strong>什么是“已激活授权”？</strong><p className="muted">用户输入卡密后，系统会生成一条已激活授权，并把它和设备绑定。你主要需要关注授权状态、套餐和到期时间，不需要理解内部编号。</p></div>
      <div className="panel">
        <div className="toolbar">
          <select value={f.status} onChange={(e) => { setOffset(0); setF({ ...f, status: e.target.value }) }}>
            <option value="">全部状态</option>
            {['active', 'frozen', 'revoked', 'voided'].map((s) => <option key={s} value={s}>{{
              active: '正常', frozen: '已冻结', revoked: '已吊销', voided: '已作废',
            }[s]}</option>)}
          </select>
          <input placeholder="按卡密前缀搜索（如 AB3KF）" value={f.q} onChange={(e) => { setOffset(0); setF({ ...f, q: e.target.value.toUpperCase() }) }} />
          <button className="ghost" disabled={loading || busy} onClick={() => void load()}>刷新</button>
        </div>
        {err && <div className="error-text">{err}</div>}
        <table>
          <thead>
            <tr><th>许可证 ID</th><th>状态</th><th>激活时间</th><th>到期时间</th><th>策略版本</th><th>备注</th><th>操作</th></tr>
          </thead>
          <tbody>
            {items.map((l) => (
              <tr key={l.id}>
                <td><Link to={`/licenses/${l.id}`} className="mono">{l.id.slice(0, 8)}…</Link></td>
                <td><Badge status={l.status} /></td>
                <td className="muted">{fmtTime(l.activated_at)}</td>
                <td className="muted">{l.expires_at ? fmtTime(l.expires_at) : '永久'}</td>
                <td className="mono">v{l.policy_version}</td>
                <td className="muted">{l.note || '—'}</td>
                  <td>
                    {canManage && l.status === 'active' && <button className="warn small" disabled={busy} onClick={() => void act(l.id, 'freeze')}>冻结</button>}
                    {canManage && l.status === 'frozen' && <button className="small" disabled={busy} onClick={() => void act(l.id, 'unfreeze')}>解冻</button>}
                    {canManage && (l.status === 'active' || l.status === 'frozen') && <button className="danger small" disabled={busy} onClick={() => void act(l.id, 'revoke')}>吊销</button>}
                  </td>
              </tr>
            ))}
            {loading ? <tr><td colSpan={7} className="muted">加载中…</td></tr> : items.length === 0 && <tr><td colSpan={7} className="muted">无匹配许可证</td></tr>}
          </tbody>
        </table>
        <Pager total={total} limit={50} offset={offset} onPage={setOffset} />
      </div>
    </>
  )
}
