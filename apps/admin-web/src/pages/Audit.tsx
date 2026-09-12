import { useCallback, useEffect, useState } from 'react'
import { get, qs } from '../api'
import { Pager, fmtTime } from '../components'

interface AuditLog {
  id: number
  ts: string
  admin_username: string | null
  action: string
  target_type: string | null
  target_id: string | null
  before_state: unknown
  after_state: unknown
  detail: unknown
  ip: string | null
  request_id: string | null
}

export default function Audit() {
  const [items, setItems] = useState<AuditLog[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [f, setF] = useState({ action: '' })
  const [err, setErr] = useState('')

  const load = useCallback(() => {
    get<{ items: AuditLog[]; total: number }>(`/admin/v1/audit${qs({ ...f, limit: 50, offset })}`)
      .then((r) => { setItems(r.items); setTotal(r.total) })
      .catch((e) => setErr(e.message))
  }, [f, offset])
  useEffect(load, [load])

  return (
    <>
      <h2 className="page-title">审计日志</h2>
      <div className="panel">
        <div className="toolbar">
          <input placeholder="按 action 过滤（如 card.revoke）" value={f.action} onChange={(e) => { setOffset(0); setF({ ...f, action: e.target.value }) }} />
          <button className="ghost" onClick={load}>刷新</button>
        </div>
        {err && <div className="error-text">{err}</div>}
        <div className="table-wrap"><table>
          <thead>
            <tr><th>时间</th><th>操作者</th><th>动作</th><th>对象</th><th>来源 IP</th><th>详情</th></tr>
          </thead>
          <tbody>
            {items.map((l) => (
              <tr key={l.id}>
                <td className="muted">{fmtTime(l.ts)}</td>
                <td className="mono">{l.admin_username || '—'}</td>
                <td><span className="badge">{l.action}</span></td>
                <td className="mono">{l.target_type}:{(l.target_id || '').slice(0, 8)}</td>
                <td className="mono">{l.ip || '—'}</td>
                <td className="muted mono" style={{ maxWidth: 380, wordBreak: 'break-all' }}>
                  {JSON.stringify(l.detail ?? {})}
                </td>
              </tr>
            ))}
            {items.length === 0 && <tr><td colSpan={6} className="muted">无记录</td></tr>}
          </tbody>
        </table></div>
        <Pager total={total} limit={50} offset={offset} onPage={setOffset} />
      </div>
    </>
  )
}
