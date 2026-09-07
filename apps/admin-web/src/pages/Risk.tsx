import { useCallback, useEffect, useState } from 'react'
import { get, post } from '../api'
import { Badge, Field, Modal, fmtTime } from '../components'

interface RiskEvent {
  id: number
  ts: string
  kind: string
  severity: string
  subject: string | null
  action: string
  detail: unknown
}
interface Ban {
  id: string
  kind: string
  value: string
  reason: string | null
  until: string | null
  created_at: string
}

export default function Risk() {
  const [events, setEvents] = useState<RiskEvent[]>([])
  const [bans, setBans] = useState<Ban[]>([])
  const [show, setShow] = useState(false)
  const [err, setErr] = useState('')
  const [form, setForm] = useState({ kind: 'ip', value: '', reason: '', until: '' })

  const load = useCallback(() => {
    get<{ items: RiskEvent[] }>('/admin/v1/risk').then((r) => setEvents(r.items)).catch((e) => setErr(e.message))
    get<{ items: Ban[] }>('/admin/v1/bans').then((r) => setBans(r.items)).catch(() => {})
  }, [])
  useEffect(load, [load])

  const create = async () => {
    await post('/admin/v1/bans', { ...form, until: form.until || undefined })
    setShow(false)
    load()
  }
  const del = async (kind: string, value: string) => {
    await post('/admin/v1/bans/delete', { kind, value })
    load()
  }

  return (
    <>
      <h2 className="page-title">风控与封禁</h2>
      <div className="panel">
        <div className="toolbar"><button onClick={() => setShow(true)}>新增封禁</button></div>
        {err && <div className="error-text">{err}</div>}
        <table>
          <thead><tr><th>封禁类型</th><th>封禁值</th><th>原因</th><th>到期</th><th>操作</th></tr></thead>
          <tbody>
            {bans.map((b) => (
              <tr key={b.id}>
                <td><span className="badge">{{
                  ip: 'IP 地址', device: '设备', card_prefix: '卡密前缀',
                  client_version: '客户端版本', asn: '运营商',
                }[b.kind] || b.kind}</span></td>
                <td className="mono">{b.value}</td>
                <td className="muted">{b.reason || '—'}</td>
                <td className="muted">{b.until ? fmtTime(b.until) : '永久'}</td>
                <td><button className="small" onClick={() => del(b.kind, b.value)}>解除</button></td>
              </tr>
            ))}
            {bans.length === 0 && <tr><td colSpan={5} className="muted">无封禁</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>风险事件（最近 200 条）</h3>
        <table>
          <thead><tr><th>时间</th><th>类型</th><th>严重度</th><th>处置</th><th>主体</th><th>详情</th></tr></thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id}>
                <td className="muted">{fmtTime(ev.ts)}</td>
                <td className="mono">{ev.kind}</td>
                <td><Badge status={ev.severity} /></td>
                <td><span className="badge">{ev.action}</span></td>
                <td className="mono">{ev.subject || '—'}</td>
                <td className="muted mono" style={{ maxWidth: 360, wordBreak: 'break-all' }}>{JSON.stringify(ev.detail ?? {})}</td>
              </tr>
            ))}
            {events.length === 0 && <tr><td colSpan={6} className="muted">无风险事件</td></tr>}
          </tbody>
        </table>
      </div>
      {show && (
        <Modal title="新增封禁" onClose={() => setShow(false)}>
          <div className="form-grid">
            <Field label="类型">
              <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
                {['ip', 'device', 'card_prefix', 'client_version', 'asn'].map((k) => <option key={k} value={k}>{{
                  ip: 'IP 地址', device: '设备', card_prefix: '卡密前缀',
                  client_version: '客户端版本', asn: '运营商网络',
                }[k]}</option>)}
              </select>
            </Field>
            <Field label="值"><input value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} /></Field>
            <Field label="原因"><input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} /></Field>
            <Field label="到期时间（留空=永久）">
              <input type="datetime-local" value={form.until} onChange={(e) => setForm({ ...form, until: e.target.value })} />
            </Field>
          </div>
          <div className="actions">
            <button className="ghost" onClick={() => setShow(false)}>取消</button>
            <button onClick={create} disabled={!form.value}>创建</button>
          </div>
        </Modal>
      )}
    </>
  )
}
