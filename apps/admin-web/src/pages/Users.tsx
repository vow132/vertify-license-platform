import { useCallback, useEffect, useState } from 'react'
import { get, post, qs } from '../api'
import { Badge, Modal, Pager, Field, fmtTime } from '../components'

interface EndUser {
  id: string
  product_id: string
  username: string
  status: string
  expires_at: string
  machine_bound_at: string | null
  last_login_at: string | null
  last_ip: string | null
  note: string | null
  created_at: string
}

interface Log {
  id: number
  kind: string
  ip: string | null
  detail: unknown
  created_at: string
}


export default function Users() {
  const [items, setItems] = useState<EndUser[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [f, setF] = useState({ status: '', q: '' })
  const [err, setErr] = useState('')
  const [detail, setDetail] = useState<{ user: EndUser; logs: Log[] } | null>(null)
  const [extend, setExtend] = useState<{ user: EndUser; days: string } | null>(null)

  const load = useCallback(() => {
    get<{ items: EndUser[]; total: number }>(`/admin/v1/users${qs({ ...f, limit: 50, offset })}`)
      .then((r) => { setItems(r.items); setTotal(r.total) })
      .catch((e) => setErr(e.message))
  }, [f, offset])
  useEffect(load, [load])

  const act = async (id: string, action: string, extra?: Record<string, unknown>) => {
    await post(`/admin/v1/users/${id}/action`, { action, ...extra })
    load()
  }

  const openDetail = async (id: string) => {
    try {
      const d = await get<{ user: EndUser; logs: Log[] }>(`/admin/v1/users/${id}`)
      setDetail(d)
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <>
      <h2 className="page-title">用户管理（账号制）</h2>
      <div className="panel">
        <div className="toolbar">
          <select value={f.status} onChange={(e) => { setOffset(0); setF({ ...f, status: e.target.value }) }}>
            <option value="">全部状态</option>
            {['active', 'disabled'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input placeholder="按用户名搜索" value={f.q} onChange={(e) => { setOffset(0); setF({ ...f, q: e.target.value }) }} />
          <button className="ghost" onClick={load}>刷新</button>
        </div>
        {err && <div className="error-text">{err}</div>}
        <div className="table-wrap"><table>
          <thead>
            <tr><th>用户名</th><th>状态</th><th>到期时间</th><th>最近登录</th><th>IP</th><th>操作</th></tr>
          </thead>
          <tbody>
            {items.map((u) => (
              <tr key={u.id}>
                <td className="mono">{u.username}</td>
                <td><Badge status={u.status} /></td>
                <td className="muted">{fmtTime(u.expires_at)}</td>
                <td className="muted">{fmtTime(u.last_login_at)}</td>
                <td className="mono">{u.last_ip || '—'}</td>
                <td>
                  <button className="small" onClick={() => openDetail(u.id)}>日志</button>{' '}
                  <button className="small" onClick={() => setExtend({ user: u, days: '30' })}>续期</button>{' '}
                  {u.status === 'active' ? (
                    <button className="warn small" onClick={async () => {
                      const reason = prompt('禁用原因：')
                      if (!reason) return
                      await act(u.id, 'disable', { reason })
                    }}>禁用</button>
                  ) : (
                    <button className="small" onClick={() => act(u.id, 'enable')}>启用</button>
                  )}{' '}
                  {u.machine_bound_at && (
                    <button className="warn small" onClick={async () => {
                      if (!confirm('确认解绑该用户的机器？')) return
                      await act(u.id, 'reset-machine')
                    }}>解绑机器</button>
                  )}
                </td>
              </tr>
            ))}
            {items.length === 0 && <tr><td colSpan={6} className="muted">无用户</td></tr>}
          </tbody>
        </table></div>
        <Pager total={total} limit={50} offset={offset} onPage={setOffset} />
      </div>

      {detail && (
        <Modal title={`用户 ${detail.user.username} 的日志`} onClose={() => setDetail(null)}>
          <div className="table-wrap"><table>
            <thead><tr><th>时间</th><th>事件</th><th>IP</th></tr></thead>
            <tbody>
              {detail.logs.map((l) => (
                <tr key={l.id}>
                  <td className="muted">{fmtTime(l.created_at)}</td>
                  <td><span className="badge">{l.kind}</span></td>
                  <td className="mono">{l.ip || '—'}</td>
                </tr>
              ))}
              {detail.logs.length === 0 && <tr><td colSpan={3} className="muted">无日志</td></tr>}
            </tbody>
          </table></div>
        </Modal>
      )}

      {extend && (
        <Modal title={`续期 — ${extend.user.username}（当前至 ${fmtTime(extend.user.expires_at)}）`} onClose={() => setExtend(null)}>
          <div className="form-grid">
            <Field label="延长天数"><input type="number" value={extend.days} onChange={(e) => setExtend({ ...extend, days: e.target.value })} /></Field>
          </div>
          <div className="actions">
            <button className="ghost" onClick={() => setExtend(null)}>取消</button>
            <button onClick={async () => {
              await act(extend.user.id, 'extend', { days: Number(extend.days) })
              setExtend(null)
            }} disabled={!extend.days || Number(extend.days) <= 0}>确认续期</button>
          </div>
        </Modal>
      )}
    </>
  )
}
