import { useCallback, useEffect, useState } from 'react'
import { get, post } from '../api'
import { Badge, Field, Modal, fmtTime } from '../components'

const yuan = (cents: number) => (cents / 100).toFixed(2) + ' 元'

interface Agent {
  id: string
  name: string
  balance_cents: number
  status: string
  created_at: string
}

interface Transaction {
  id: number
  amount_cents: number
  balance_after: number
  kind: string
  ref_batch_id: string | null
  note: string | null
  created_at: string
}

export default function Agents() {
  const [items, setItems] = useState<Agent[]>([])
  const [show, setShow] = useState(false)
  const [name, setName] = useState('')
  const [acct, setAcct] = useState({ username: '', password: '' })
  const [created, setCreated] = useState<{ name: string; username: string; password: string } | null>(null)
  const [err, setErr] = useState('')
  const [bal, setBal] = useState<{ agent: Agent; amount: string; note: string } | null>(null)
  const [transactions, setTransactions] = useState<{ agent: Agent; items: Transaction[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const load = useCallback(() => {
    get<{ items: Agent[] }>('/admin/v1/agents').then((r) => { setItems(r.items); setErr('') }).catch((e) => setErr((e as Error).message))
  }, [])
  useEffect(load, [load])

  const genPassword = () => {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
    const buf = new Uint32Array(16)
    crypto.getRandomValues(buf)
    setAcct((a) => ({ ...a, password: Array.from(buf, (n) => alphabet[n % alphabet.length]).join('') }))
  }

  const viewTransactions = async (agent: Agent) => {
    try {
      const r = await get<{ items: Transaction[] }>(`/admin/v1/agents/${agent.id}/transactions`)
      setTransactions({ agent, items: r.items || [] })
    } catch (e) { setErr((e as Error).message) }
  }

  const create = async () => {
    if (busy) return
    setBusy(true)
    try {
      const withAccount = acct.username.trim() !== ''
      const r = await post<{ account?: { username: string; password?: string } }>('/admin/v1/agents', {
        name: name.trim(),
        ...(withAccount ? { account_username: acct.username.trim(), account_password: acct.password } : {}),
      })
      setShow(false)
      if (r.account) {
        setCreated({ name: name.trim(), username: r.account.username, password: r.account.password || '' })
      }
      setName('')
      setAcct({ username: '', password: '' })
      load()
    } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }

  return (
    <>
      <h2 className="page-title">代理商</h2>
      <div className="panel">
        <div className="toolbar">
          <button onClick={() => setShow(true)}>新建代理商</button>
          <span className="muted">制卡扣费：套餐定价 &gt; 0 时，代理制卡按 数量×单价 扣余额</span>
        </div>
        {err && <div className="error-text">{err}</div>}
        <div className="table-wrap"><table>
          <thead><tr><th>名称</th><th>余额</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id}>
                <td>{a.name}</td>
                <td><span className="badge info">{yuan(a.balance_cents)}</span></td>
                <td><Badge status={a.status} /></td>
                <td className="muted">{fmtTime(a.created_at)}</td>
                <td>
                  <button className="small" onClick={() => viewTransactions(a)} style={{ marginRight: 6 }}>流水</button>
                  <button className="small" onClick={() => setBal({ agent: a, amount: '', note: '' })} style={{ marginRight: 6 }}>调整余额</button>
                  {a.status === 'active' ? (
                    <button className="warn small" disabled={busy} onClick={async () => { try { setBusy(true); await post(`/admin/v1/agents/${a.id}/status`, { status: 'suspended' }); load() } catch (e) { setErr((e as Error).message) } finally { setBusy(false) } }}>停用</button>
                  ) : (
                    <button className="small" disabled={busy} onClick={async () => { try { setBusy(true); await post(`/admin/v1/agents/${a.id}/status`, { status: 'active' }); load() } catch (e) { setErr((e as Error).message) } finally { setBusy(false) } }}>启用</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>
      {bal && (
        <Modal title={`调整余额 — ${bal.agent.name}（当前 ${yuan(bal.agent.balance_cents)}）`} onClose={() => setBal(null)}>
          <div className="form-grid">
            <Field label="金额（元，正=充值，负=调差）" full>
              <input type="number" step="0.01" value={bal.amount} onChange={(e) => setBal({ ...bal, amount: e.target.value })} placeholder="如 100 或 -20" />
            </Field>
            <Field label="备注" full>
              <input value={bal.note} onChange={(e) => setBal({ ...bal, note: e.target.value })} />
            </Field>
          </div>
          <div className="actions">
            <button className="ghost" onClick={() => setBal(null)}>取消</button>
            <button onClick={async () => {
              if (busy) return
              const amount = Number(bal?.amount)
              if (!Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 9000000000) { setErr('金额必须是有限且在范围内的非零数字'); return }
              try {
                setBusy(true)
                await post(`/admin/v1/agents/${bal.agent.id}/balance`, {
                  amount_yuan: amount, note: bal.note.trim(),
                })
                setBal(null)
                load()
              } catch (e) {
                setErr((e as Error).message)
              } finally { setBusy(false) }
            }} disabled={busy || !bal.amount || !Number.isFinite(Number(bal.amount)) || Number(bal.amount) === 0}>{busy ? '提交中…' : '确认'}</button>
          </div>
        </Modal>
      )}
      {transactions && (
        <Modal title={`余额流水 — ${transactions.agent.name}`} onClose={() => setTransactions(null)}>
          <div className="table-wrap"><table>
            <thead><tr><th>时间</th><th>类型</th><th>变动</th><th>变动后余额</th><th>备注</th></tr></thead>
            <tbody>
              {transactions.items.map((t) => <tr key={t.id}>
                <td className="muted">{fmtTime(t.created_at)}</td>
                <td>{t.kind === 'topup' ? '充值' : t.kind === 'adjust' ? '余额调差' : t.kind === 'batch_purchase' ? '制卡扣款' : t.kind}</td>
                <td className={t.amount_cents >= 0 ? 'ok-text' : 'error-text'}>{t.amount_cents >= 0 ? '+' : ''}{yuan(t.amount_cents)}</td>
                <td>{yuan(t.balance_after)}</td>
                <td>{t.note || '—'}</td>
              </tr>)}
              {transactions.items.length === 0 && <tr><td colSpan={5} className="muted">暂无流水</td></tr>}
            </tbody>
          </table></div>
        </Modal>
      )}

      {created && (
        <Modal title="代理商登录账号已创建" onClose={() => setCreated(null)}>
          <p className="muted" style={{ marginTop: 0 }}>
            请立即保存以下账号密码（密码不会再次显示）。代理商首次登录时会被要求修改密码。
          </p>
          <div className="kv">
            <span className="k">代理商</span><span>{created.name}</span>
            <span className="k">登录账号</span><span className="mono">{created.username}</span>
            <span className="k">初始密码</span><span className="mono">{created.password || '（未生成）'}</span>
          </div>
          <div className="actions">
            <button
              className="ghost"
              onClick={() => navigator.clipboard?.writeText(`账号 ${created.username} 密码 ${created.password}`).then(() => setErr('')).catch(() => setErr('复制失败，请手动复制'))}
            >
              复制账号密码
            </button>
            <button onClick={() => setCreated(null)}>我已保存</button>
          </div>
        </Modal>
      )}

      {show && (
        <Modal title="新建代理商" onClose={() => setShow(false)}>
          <Field label="名称"><input value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="登录账号（可选）" full>
            <input value={acct.username} onChange={(e) => setAcct({ ...acct, username: e.target.value })} placeholder="留空则只创建代理商，不生成登录账号" />
          </Field>
          <Field label="初始密码（≥12 位）" full>
            <div style={{ display: 'flex', gap: 8 }}>
              <input style={{ flex: 1 }} value={acct.password} onChange={(e) => setAcct({ ...acct, password: e.target.value })} placeholder="填写登录账号后需设置初始密码" />
              <button className="ghost" type="button" onClick={genPassword}>随机生成</button>
            </div>
          </Field>
          <div className="actions">
            <button className="ghost" onClick={() => setShow(false)}>取消</button>
            <button
              onClick={create}
              disabled={busy || !name.trim() || (acct.username.trim() !== '' && acct.password.length < 12)}
            >
              {busy ? '创建中…' : acct.username.trim() ? '创建代理商并生成账号' : '创建'}
            </button>
          </div>
        </Modal>
      )}
    </>
  )
}
