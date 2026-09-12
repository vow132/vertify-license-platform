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

interface ProductLite {
  id: string
  code: string
  name: string
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
  // 产品权限弹窗
  const [grants, setGrants] = useState<{ agent: Agent; products: ProductLite[]; selected: Set<string> } | null>(null)
  // 账号管理弹窗
  const [accMgr, setAccMgr] = useState<{
    agent: Agent
    adminId: string
    username: string
    newUsername: string
    newPassword: string
  } | null>(null)
  const [accResult, setAccResult] = useState<{ username: string; password: string } | null>(null)
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

  const openGrants = async (agent: Agent) => {
    try {
      const [pr, gr] = await Promise.all([
        get<{ items: ProductLite[] }>('/admin/v1/products'),
        get<{ items: string[] }>(`/admin/v1/agents/${agent.id}/products`),
      ])
      setGrants({ agent, products: pr.items || [], selected: new Set(gr.items || []) })
    } catch (e) { setErr((e as Error).message) }
  }

  const toggleGrant = async (productID: string, granted: boolean) => {
    if (!grants || busy) return
    setBusy(true)
    try {
      await post(`/admin/v1/agents/${grants.agent.id}/products`, { product_id: productID, granted })
      // 函数式更新：避免连续切换时基于旧快照互相覆盖
      setGrants((g) => (g ? { ...g, selected: granted ? new Set(g.selected).add(productID) : new Set([...g.selected].filter((x) => x !== productID)) } : g))
    } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }

  const openAccMgr = async (agent: Agent) => {
    try {
      const r = await get<{ username: string }>(`/admin/v1/agents/${agent.id}/account`)
      setAccMgr({ agent, adminId: '', username: r.username, newUsername: '', newPassword: '' })
      // 拿 adminId：从管理员列表找该代理绑定的账号
      const admins = await get<{ items: { id: string; username: string; agent_id: string | null }[] }>('/admin/v1/admins')
      const found = (admins.items || []).find((x) => x.username === r.username)
      setAccMgr({ agent, adminId: found?.id || '', username: r.username, newUsername: '', newPassword: '' })
    } catch (e) { setErr((e as Error).message) }
  }

  const genMgrPassword = () => {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
    const buf = new Uint32Array(16)
    crypto.getRandomValues(buf)
    setAccMgr((m) => (m ? { ...m, newPassword: Array.from(buf, (n) => alphabet[n % alphabet.length]).join('') } : m))
  }

  const submitAccMgr = async () => {
    if (!accMgr || busy) return
    setBusy(true)
    try {
      const r = await post<{ username: string; new_password?: string }>(`/admin/v1/agents/${accMgr.agent.id}/account`, {
        admin_id: accMgr.adminId,
        new_username: accMgr.newUsername.trim() || undefined,
        new_password: accMgr.newPassword || undefined,
      })
      setAccResult({ username: r.username, password: r.new_password || '' })
      setAccMgr(null)
    } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
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
      window.dispatchEvent(new Event('vft:me-refresh'))
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
                  <button className="small" onClick={() => openGrants(a)} style={{ marginRight: 6 }}>产品权限</button>
                  <button className="small" onClick={() => openAccMgr(a)} style={{ marginRight: 6 }}>登录账号</button>
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
                window.dispatchEvent(new Event('vft:me-refresh'))
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

      {grants && (
        <Modal title={`产品权限 — ${grants.agent.name}`} onClose={() => setGrants(null)}>
          <p className="muted" style={{ marginTop: 0 }}>勾选 = 该代理商可以制卡和查看此产品的卡密；未勾选的产品对代理商完全不可见。</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {grants.products.map((p) => (
              <label key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={grants.selected.has(p.id)}
                  disabled={busy}
                  onChange={(e) => toggleGrant(p.id, e.target.checked)}
                />
                <span>{p.code} · {p.name}</span>
              </label>
            ))}
            {grants.products.length === 0 && <span className="muted">暂无产品，请先到产品管理新增。</span>}
          </div>
          {err && <div className="error-text">{err}</div>}
          <div className="actions">
            <button className="ghost" onClick={() => setGrants(null)}>关闭</button>
          </div>
        </Modal>
      )}

      {accMgr && (
        <Modal title={`登录账号 — ${accMgr.agent.name}`} onClose={() => setAccMgr(null)}>
          <div className="form-grid">
            <Field label="当前用户名" full><input value={accMgr.username} disabled /></Field>
            <Field label="新用户名（可选）" full>
              <input value={accMgr.newUsername} onChange={(e) => setAccMgr({ ...accMgr, newUsername: e.target.value })} placeholder="留空表示不修改用户名" />
            </Field>
            <Field label="重置密码（可选，≥12 位）" full>
              <div style={{ display: 'flex', gap: 8 }}>
                <input style={{ flex: 1 }} value={accMgr.newPassword} onChange={(e) => setAccMgr({ ...accMgr, newPassword: e.target.value })} placeholder="留空表示不修改密码" />
                <button className="ghost" type="button" onClick={genMgrPassword}>随机生成</button>
              </div>
            </Field>
          </div>
          <p className="muted">重置密码后，该代理商的现有登录会立即失效，且下次登录会被要求修改密码。</p>
          {err && <div className="error-text">{err}</div>}
          <div className="actions">
            <button className="ghost" onClick={() => setAccMgr(null)}>取消</button>
            <button
              onClick={submitAccMgr}
              disabled={busy || (!accMgr.newUsername.trim() && !accMgr.newPassword) || (accMgr.newPassword !== '' && accMgr.newPassword.length < 12)}
            >
              {busy ? '提交中…' : '保存修改'}
            </button>
          </div>
        </Modal>
      )}

      {accResult && (
        <Modal title="代理商账号已更新" onClose={() => setAccResult(null)}>
          <p className="muted" style={{ marginTop: 0 }}>请立即保存（新密码不会再次显示）：</p>
          <div className="kv">
            <span className="k">登录账号</span><span className="mono">{accResult.username}</span>
            {accResult.password && (<><span className="k">新密码</span><span className="mono">{accResult.password}</span></>)}
          </div>
          <div className="actions">
            <button className="ghost" onClick={() => navigator.clipboard?.writeText(`账号 ${accResult.username} 密码 ${accResult.password}`).catch(() => setErr('复制失败'))}>复制</button>
            <button onClick={() => setAccResult(null)}>我已保存</button>
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
