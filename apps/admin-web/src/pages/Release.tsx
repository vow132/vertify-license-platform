import { useCallback, useEffect, useState } from 'react'
import { del, get, post } from '../api'
import { Badge, fmtTime } from '../components'

interface Product { id: string; code: string; name: string }
interface Message { id: number; product_id: string; content: string; enabled: boolean; created_at: string }
interface Version {
  id: number
  product_id: string
  version: string
  download_url: string
  notes: string | null
  force_update: boolean
  created_at: string
}

// 软件发布：公告（留言）+ 版本管理
export default function Release() {
  const [products, setProducts] = useState<Product[]>([])
  const [messages, setMessages] = useState<Message[]>([])
  const [versions, setVersions] = useState<Version[]>([])
  const [err, setErr] = useState('')
  const [msgForm, setMsgForm] = useState({ product_id: '', content: '' })
  const [verForm, setVerForm] = useState({ product_id: '', version: '', download_url: '', notes: '', force_update: false })
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    setErr('')
    get<{ items: Product[] }>('/admin/v1/products').then((r) => setProducts(r.items)).catch((e) => setErr((e as Error).message))
    get<{ items: Message[] }>('/admin/v1/messages').then((r) => setMessages(r.items)).catch((e) => setErr((e as Error).message))
    get<{ items: Version[] }>('/admin/v1/versions').then((r) => setVersions(r.items)).catch((e) => setErr((e as Error).message))
  }, [])
  useEffect(load, [load])

  const prodCode = (id: string) => products.find((p) => p.id === id)?.code || id.slice(0, 8)

  return (
    <>
      <h2 className="page-title">软件发布</h2>
      {err && <div className="panel error-text">{err}</div>}

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>软件公告（客户端登录时下发）</h3>
        <div className="toolbar">
          <select value={msgForm.product_id} onChange={(e) => setMsgForm({ ...msgForm, product_id: e.target.value })}>
            <option value="">选择产品…</option>
            {products.map((p) => <option key={p.id} value={p.id}>{p.code} · {p.name}</option>)}
          </select>
          <input style={{ flex: 1, minWidth: 240 }} placeholder="公告内容" value={msgForm.content}
            onChange={(e) => setMsgForm({ ...msgForm, content: e.target.value })} />
          <button disabled={busy || !msgForm.product_id || !msgForm.content.trim()}
            onClick={async () => {
              if (busy) return
              setBusy(true)
              try {
                await post('/admin/v1/messages', { ...msgForm, content: msgForm.content.trim() })
                setMsgForm({ product_id: '', content: '' })
                load()
              } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
            }}>发布公告</button>
        </div>
        <table>
          <thead><tr><th>产品</th><th>内容</th><th>状态</th><th>发布时间</th><th>操作</th></tr></thead>
          <tbody>
            {messages.map((m) => (
              <tr key={m.id}>
                <td className="mono">{prodCode(m.product_id)}</td>
                <td>{m.content}</td>
                <td>{m.enabled ? <Badge status="active" /> : <Badge status="retired" />}</td>
                <td className="muted">{fmtTime(m.created_at)}</td>
                <td>
                  <button className="ghost small" disabled={busy} onClick={async () => {
                    try { await post(`/admin/v1/messages/${m.id}/enabled`, { enabled: !m.enabled }); load() } catch (e) { setErr((e as Error).message) }
                  }}>{m.enabled ? '停用' : '启用'}</button>{' '}
                  <button className="danger small" disabled={busy} onClick={async () => {
                    if (!confirm('确认删除该公告？')) return
                    try { await del(`/admin/v1/messages/${m.id}`); load() } catch (e) { setErr((e as Error).message) }
                  }}>删除</button>
                </td>
              </tr>
            ))}
            {messages.length === 0 && <tr><td colSpan={5} className="muted">暂无公告</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>版本管理（客户端取版本/强制更新）</h3>
        <div className="toolbar">
          <select value={verForm.product_id} onChange={(e) => setVerForm({ ...verForm, product_id: e.target.value })}>
            <option value="">选择产品…</option>
            {products.map((p) => <option key={p.id} value={p.id}>{p.code} · {p.name}</option>)}
          </select>
          <input placeholder="版本号 (1.2.0)" style={{ width: 120 }} value={verForm.version}
            onChange={(e) => setVerForm({ ...verForm, version: e.target.value })} />
          <input placeholder="下载地址" style={{ flex: 1, minWidth: 220 }} value={verForm.download_url}
            onChange={(e) => setVerForm({ ...verForm, download_url: e.target.value })} />
          <input placeholder="更新说明" style={{ width: 160 }} value={verForm.notes}
            onChange={(e) => setVerForm({ ...verForm, notes: e.target.value })} />
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <input type="checkbox" checked={verForm.force_update}
              onChange={(e) => setVerForm({ ...verForm, force_update: e.target.checked })} />强制更新
          </label>
          <button disabled={busy || !verForm.product_id || !verForm.version.trim() || !verForm.download_url.trim()}
            onClick={async () => {
              if (busy) return
              setBusy(true)
              try {
                await post('/admin/v1/versions', { ...verForm, version: verForm.version.trim(), download_url: verForm.download_url.trim(), notes: verForm.notes.trim() })
                setVerForm({ product_id: '', version: '', download_url: '', notes: '', force_update: false })
                load()
              } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
            }}>{busy ? '发布中…' : '发布版本'}</button>
        </div>
        <table>
          <thead><tr><th>产品</th><th>版本</th><th>下载地址</th><th>强制</th><th>发布时间</th><th>操作</th></tr></thead>
          <tbody>
            {versions.map((v) => (
              <tr key={v.id}>
                <td className="mono">{prodCode(v.product_id)}</td>
                <td className="mono">{v.version}</td>
                <td className="mono" style={{ maxWidth: 260, wordBreak: 'break-all' }}>{v.download_url}</td>
                <td>{v.force_update ? <span className="badge ok">是</span> : <span className="muted">否</span>}</td>
                <td className="muted">{fmtTime(v.created_at)}</td>
                <td><button className="danger small" disabled={busy} onClick={async () => {
                  if (!confirm(`确认删除版本 ${v.version}？`)) return
                  try { await del(`/admin/v1/versions/${v.id}`); load() } catch (e) { setErr((e as Error).message) }
                }}>删除</button></td>
              </tr>
            ))}
            {versions.length === 0 && <tr><td colSpan={6} className="muted">暂无版本</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  )
}
