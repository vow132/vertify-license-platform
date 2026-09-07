import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { get, post, qs } from '../api'
import { Badge, Field, Modal, Pager, fmtTime } from '../components'
import { usePermissions } from '../auth'

interface Card {
  id: string
  batch_id: string
  agent_id: string | null
  agent_name: string | null
  product_id: string
  plan_id: string
  prefix: string
  plan_kind: string
  duration_days: number
  fixed_expiry_days: number
  kind: string
  status: string
  uses_total: number
  uses_left: number
  price_cents: number
  note: string | null
  license_id: string | null
  activated_at: string | null
  expires_at: string | null
  created_at: string
}

interface Agent { id: string; name: string }
interface Plan { id: string; product_id: string; code: string; name: string }
interface Product { id: string; code: string; name: string }

export default function Cards() {
  const [items, setItems] = useState<Card[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [agents, setAgents] = useState<Agent[]>([])
  const [plans, setPlans] = useState<Plan[]>([])
  const [products, setProducts] = useState<Product[]>([])
  const [f, setF] = useState({ status: '', q: '', agent_id: '', kind: '', product_id: '', plan_id: '' })
  const [err, setErr] = useState('')
  const [detail, setDetail] = useState<Card | null>(null)
  const [noteEdit, setNoteEdit] = useState<{ id: string; note: string } | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [importProduct, setImportProduct] = useState('')
  const [importPlan, setImportPlan] = useState('')
  const [importKind, setImportKind] = useState('license')
  const [importMsg, setImportMsg] = useState('')
  const [importBusy, setImportBusy] = useState(false)
  const [revealed, setRevealed] = useState('')
  const [bulkAction, setBulkAction] = useState('')
  const [bulkReason, setBulkReason] = useState('')
  const [bulkBusy, setBulkBusy] = useState(false)
  const [bulkMsg, setBulkMsg] = useState('')
  const permissions = usePermissions()
  const canManage = permissions.includes('cards:manage')
  const canExport = permissions.includes('cards:export')
  const parsedImportCards = importText.split(/[\r\n,;]+/).map((x) => x.trim()).filter(Boolean)
  const importPlans = plans.filter((p) => !importProduct || p.product_id === importProduct)
  const runBulkAction = async () => {
    if (!bulkAction || !selected.length || bulkBusy) return
    if (bulkAction !== 'unfreeze' && !bulkReason.trim()) { setBulkMsg('请填写操作原因'); return }
    if (!confirm(`确认对选中的 ${selected.length} 张卡密执行${bulkAction === 'freeze' ? '冻结' : bulkAction === 'revoke' ? '吊销' : '解冻'}？`)) return
    setBulkBusy(true)
    setBulkMsg('')
    try {
      const r = await post<{ ok: number; failed: Record<string, string> }>('/admin/v1/cards/bulk-action', { ids: selected, action: bulkAction, reason: bulkReason.trim() })
      const failed = Object.keys(r.failed || {})
      setBulkMsg(failed.length ? `已处理 ${r.ok} 张，失败 ${failed.length} 张` : `已成功处理 ${r.ok} 张`)
      setSelected([])
      setBulkReason('')
      load()
    } catch (e) {
      setBulkMsg((e as Error).message)
    } finally {
      setBulkBusy(false)
    }
  }

  const importCards = async () => {
    if (!importProduct || !importPlan) { setImportMsg('请选择产品和套餐'); return }
    if (!parsedImportCards.length || parsedImportCards.length > 10000) { setImportMsg('请输入1-10000张卡密'); return }
    setImportBusy(true)
    try {
      const r = await post<{ imported: number }>('/admin/v1/batches/import', { product_id: importProduct, plan_id: importPlan, kind: importKind, cards: parsedImportCards })
      setImportMsg(`导入成功：${r.imported} 张`)
      setImportText('')
      load()
    } catch (e) {
      setImportMsg((e as Error).message)
    } finally {
      setImportBusy(false)
    }
  }


  const load = useCallback(() => {
    get<{ items: Card[]; total: number }>(`/admin/v1/cards${qs({ ...f, limit: 50, offset })}`)
      .then((r) => { setItems(r.items); setTotal(r.total); setSelected([]) })
      .catch((e) => setErr((e as Error).message))
  }, [f, offset])
  useEffect(load, [load])
  useEffect(() => {
    get<{ items: Agent[] }>('/admin/v1/agents').then((r) => setAgents(r.items)).catch((e) => setErr((e as Error).message))
    get<{ items: Plan[] }>('/admin/v1/plans').then((r) => setPlans(r.items)).catch((e) => setErr((e as Error).message))
    get<{ items: Product[] }>('/admin/v1/products').then((r) => setProducts(r.items)).catch((e) => setErr((e as Error).message))
  }, [])

  const [selected, setSelected] = useState<string[]>([])

  const act = async (id: string, action: string, suppliedReason?: string) => {
    const label = action === 'freeze' ? '冻结' : action === 'revoke' ? '吊销' : '作废'
    const reason = suppliedReason ?? (action !== 'unfreeze' ? prompt(`请输入${label}原因（将写入审计日志）：`) || '' : '')
    if (action !== 'unfreeze' && !reason) return
    try {
      await post(`/admin/v1/cards/${id}/action`, { action, reason })
      load()
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  const planName = (id: string) => {
    const p = plans.find((x) => x.id === id)
    return p ? `${p.name}（${p.code}）` : id.slice(0, 8) + '…'
  }
  const prodName = (id: string) => {
    const p = products.find((x) => x.id === id)
    return p ? `${p.name}（${p.code}）` : id.slice(0, 8) + '…'
  }
  const agentName = (c: Card) => c.agent_name || (c.agent_id ? '未知代理商' : '直营')
  const planDuration = (c: Card) => !c.plan_kind ? '套餐信息缺失' : c.plan_kind === 'duration' ? `${c.duration_days}天` : c.plan_kind === 'fixed' ? `固定期${c.fixed_expiry_days}天` : c.plan_kind === 'uses' ? `${c.uses_total}次` : c.plan_kind === 'permanent' ? '永久' : '套餐信息缺失'

  return (
    <>
      <h2 className="page-title">卡密管理</h2>
      <div className="panel intro-panel"><strong>卡密管理</strong><p className="muted">卡密是给用户使用的兑换码。新卡生成后可以查看、复制或下载；已激活授权可以在“已激活授权”页面查看设备和到期时间。卡密管理不会显示内部密钥或数据库编号。</p></div>
      <div className="panel">
        <div className="toolbar">
          <select value={f.status} onChange={(e) => { setOffset(0); setF({ ...f, status: e.target.value }) }}>
            <option value="">全部状态</option>
            {['unused', 'active', 'frozen', 'revoked', 'voided', 'depleted'].map((s) => (
              <option key={s} value={s}>{{
                unused: '未使用', active: '使用中', frozen: '已冻结',
                revoked: '已吊销', voided: '已作废', depleted: '已用尽',
              }[s]}</option>
            ))}
          </select>
          <select value={f.kind} onChange={(e) => { setOffset(0); setF({ ...f, kind: e.target.value }) }}>
            <option value="">全部类型</option>
            <option value="license">授权卡</option>
            <option value="renewal">续费卡</option>
          </select>
          <select value={f.agent_id} onChange={(e) => { setOffset(0); setF({ ...f, agent_id: e.target.value }) }}>
            <option value="">全部代理商</option>
            {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
          <select value={f.plan_id} onChange={(e) => { setOffset(0); setF({ ...f, plan_id: e.target.value }) }}>
            <option value="">全部套餐</option>
            {plans.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.code}</option>)}
          </select>
          <select value={f.product_id} onChange={(e) => { setOffset(0); setF({ ...f, product_id: e.target.value }) }}>
            <option value="">全部产品</option>
            {products.map((p) => <option key={p.id} value={p.id}>{p.code}</option>)}
          </select>
          <input placeholder="按前缀搜索（如 AB3KF）" value={f.q} onChange={(e) => { setOffset(0); setF({ ...f, q: e.target.value.toUpperCase() }) }} />
          {canManage && <button className="ghost" onClick={() => setImportOpen(true)}>导入卡密</button>}
          <button className="ghost" onClick={load}>刷新</button>
        </div>
        {canManage && selected.length > 0 && (
          <div className="toolbar bulk-toolbar">
            <strong>已选 {selected.length} 张</strong>
            <select value={bulkAction} onChange={(e) => setBulkAction(e.target.value)}>
              <option value="">选择批量操作…</option>
              <option value="freeze">批量冻结</option>
              <option value="unfreeze">批量解冻</option>
              <option value="revoke">批量吊销</option>
            </select>
            {bulkAction !== 'unfreeze' && <input placeholder="操作原因" value={bulkReason} onChange={(e) => setBulkReason(e.target.value)} />}
            <button className="danger small" disabled={bulkBusy || !bulkAction} onClick={runBulkAction}>{bulkBusy ? '处理中…' : '执行批量操作'}</button>
            {bulkMsg && <span className="muted">{bulkMsg}</span>}
          </div>
        )}
        {err && <div className="error-text">{err}</div>}
        <table>
          <thead>
            <tr>
              <th style={{ width: 32 }}>
                <input type="checkbox" checked={items.length > 0 && selected.length === items.length}
                  onChange={(e) => setSelected(e.target.checked ? items.map((c) => c.id) : [])} />
              </th>
              <th>前缀</th><th>类型/时长</th><th>代理商</th><th>状态</th><th>次数</th><th>激活时间</th>
              <th>许可证</th><th>操作</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id}>
                <td>
                  <input type="checkbox" checked={selected.includes(c.id)}
                    onChange={(e) => setSelected(e.target.checked ? [...selected, c.id] : selected.filter((x) => x !== c.id))} />
                </td>
                <td className="mono">{c.prefix}-****</td>
                <td>{c.kind === 'renewal' ? '续费卡' : '授权卡'} · {planDuration(c)}</td>
                <td>{agentName(c)}</td>
                <td><Badge status={c.status} /></td>
                <td>{c.uses_total > 0 ? `${c.uses_left}/${c.uses_total}` : '—'}</td>
                <td className="muted">{fmtTime(c.activated_at)}</td>
                <td>
                  {c.license_id && <Link to={`/licenses/${c.license_id}`} className="mono">{c.license_id.slice(0, 8)}…</Link>}
                  {!c.license_id && '—'}
                </td>
                <td>
                  <button className="ghost small" onClick={() => { setDetail(c); setNoteEdit({ id: c.id, note: c.note || '' }) }}>详情</button>{' '}
                  {(c.status === 'active' || c.status === 'unused') && (
                    <button className="warn small" onClick={() => act(c.id, 'freeze')}>冻结</button>
                  )}
                  {c.status === 'frozen' && <button className="small" onClick={() => act(c.id, 'unfreeze')}>解冻</button>}
                  {(c.status === 'active' || c.status === 'frozen' || c.status === 'unused') && (
                    <button className="danger small" onClick={() => act(c.id, 'revoke')}>吊销</button>
                  )}
                </td>
              </tr>
            ))}
            {items.length === 0 && <tr><td colSpan={9} className="muted">无匹配卡密</td></tr>}
          </tbody>
        </table>
        <Pager total={total} limit={50} offset={offset} onPage={setOffset} />
      </div>

      {importOpen && (
        <Modal title="导入卡密" onClose={() => { setImportOpen(false); setImportMsg('') }}>
          <p className="muted">每行一张，也支持逗号、分号分隔。导入的卡密必须是完整卡密，系统会自动去重并校验格式。</p>
          <div className="form-grid">
            <Field label="产品">
              <select value={importProduct} onChange={(e) => { setImportProduct(e.target.value); setImportPlan('') }}>
                <option value="">选择产品…</option>
                {products.map((p) => <option key={p.id} value={p.id}>{p.code} · {p.name}</option>)}
              </select>
            </Field>
            <Field label="套餐">
              <select value={importPlan} onChange={(e) => setImportPlan(e.target.value)}>
                <option value="">选择套餐…</option>
                {importPlans.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.code}</option>)}
              </select>
            </Field>
            <Field label="卡类型">
              <select value={importKind} onChange={(e) => setImportKind(e.target.value)}>
                <option value="license">授权卡</option>
                <option value="renewal">续费卡</option>
              </select>
            </Field>
            <Field label="从文件读取（可选）" full>
              <input type="file" accept=".txt,.csv" onChange={(e) => {
                const file = e.target.files?.[0]
                if (!file) return
                const reader = new FileReader()
                reader.onload = () => setImportText(String(reader.result || ''))
                reader.readAsText(file)
              }} />
            </Field>
          <Field label={`卡密内容（已解析 ${parsedImportCards.length} 张）`} full>
              <textarea rows={9} value={importText} onChange={(e) => setImportText(e.target.value)} placeholder={'例如：\nABCD2-EFGH3-JKLM4-NPQR5-STUVWX'} />
            </Field>
          </div>
          {importMsg && <div className={importMsg.startsWith('导入成功') ? 'success-text' : 'error-text'}>{importMsg}</div>}
          <div className="actions">
            <button className="ghost" onClick={() => setImportOpen(false)}>关闭</button>
            <button onClick={importCards} disabled={importBusy || !importProduct || !importPlan || !importText.trim()}>{importBusy ? '导入中…' : '开始导入'}</button>
          </div>
        </Modal>
      )}

      {detail && (
        <Modal title={`卡密详情 — ${detail.prefix}-****`} onClose={() => { setDetail(null); setRevealed('') }}>
          <div className="kv">
            <div className="k">卡密前缀</div><div className="mono">{detail.prefix}-****</div>
            <div className="k">类型/时长</div><div>{detail.kind === 'renewal' ? '续费卡' : '授权卡'} · {planDuration(detail)}</div>
            <div className="k">状态</div><div><Badge status={detail.status} /></div>
            <div className="k">单价</div><div>{(detail.price_cents / 100).toFixed(2)} 元</div>
            <div className="k">代理商</div><div>{agentName(detail)}</div>
            <div className="k">批次</div><div className="mono">{detail.batch_id}</div>
            <div className="k">产品</div><div>{prodName(detail.product_id)}</div>
            <div className="k">套餐</div><div>{planName(detail.plan_id)}</div>
            <div className="k">激活时间</div><div>{fmtTime(detail.activated_at)}</div>
            <div className="k">到期时间</div><div>{detail.expires_at ? fmtTime(detail.expires_at) : '—'}</div>
            <div className="k">创建时间</div><div className="muted">{fmtTime(detail.created_at)}</div>
            <div className="k">许可证</div>
            <div>
              {detail.license_id
                ? <Link to={`/licenses/${detail.license_id}`} className="mono">{detail.license_id}</Link>
                : '—'}
            </div>
          </div>
          <div style={{ marginTop: 14 }}>
            <Field label="备注（可编辑，写进卡密信息）">
              <input value={noteEdit?.note ?? ''} onChange={(e) => setNoteEdit({ id: detail.id, note: e.target.value })} />
            </Field>
            <button className="small" disabled={(detail.note || '') === (noteEdit?.note ?? '')}
              onClick={async () => {
                try {
                  await post(`/admin/v1/cards/${detail.id}/note`, { note: noteEdit?.note ?? '' })
                  setDetail({ ...detail, note: noteEdit?.note ?? '' })
                  load()
                } catch (e) {
                  setErr((e as Error).message)
                }
              }} style={{ marginTop: 6 }}>保存备注</button>
          </div>
                  {canExport && <div className="reveal-card-actions"><button className="small" onClick={async () => { try { const r = await post<{ card: string }>(`/admin/v1/cards/${detail.id}/reveal`, {}); setRevealed(r.card) } catch (e) { setErr((e as Error).message) } }}>查看完整卡密</button>{revealed && <button className="small" onClick={() => navigator.clipboard.writeText(revealed)}>复制完整卡密</button>}</div>}
          <p className="muted" style={{ marginBottom: 0 }}>{revealed ? <span className="mono" style={{ display: 'block', padding: 10, background: 'var(--bg-subtle)', borderRadius: 8, userSelect: 'all' }}>{revealed}</span> : '点击“查看完整卡密”后临时显示；旧卡密若未保存可恢复密文，会提示无法查看。'}</p>
          <div className="actions">
            {(detail.status === 'active' || detail.status === 'unused') && canManage && (
              <button className="warn" onClick={async () => {
                const reason = prompt('冻结原因：')
                if (!reason) return
                await act(detail.id, 'freeze', reason)
                setDetail(null)
              }}>冻结</button>
            )}
            {detail.status === 'frozen' && (
              <button onClick={async () => { await act(detail.id, 'unfreeze'); setDetail(null) }}>解冻</button>
            )}
            {(detail.status === 'active' || detail.status === 'frozen' || detail.status === 'unused') && canManage && (
              <button className="danger" onClick={async () => {
                const reason = prompt('吊销原因：')
                if (!reason) return
                await act(detail.id, 'revoke', reason)
                setDetail(null)
              }}>吊销</button>
            )}
            <button className="ghost" onClick={() => setDetail(null)}>关闭</button>
          </div>
        </Modal>
      )}
    </>
  )
}
