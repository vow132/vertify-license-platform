import { useCallback, useEffect, useState } from 'react'
import { get, post, qs } from '../api'
import { Field, Modal, Pager, fmtTime } from '../components'
import { usePermissions } from '../auth'

interface Batch {
  id: string
  product_id: string
  plan_id: string
  quantity: number
  prefix: string
  note: string | null
  created_at: string
}

interface Plan {
  id: string
  product_id: string
  code: string
  name: string
  kind: string
  duration_days: number
  fixed_expiry_days: number
  uses_total: number
  price_cents: number
}
interface Product {
  id: string
  code: string
  name: string
}

export default function Batches() {
  const [items, setItems] = useState<Batch[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [products, setProducts] = useState<Product[]>([])
  const [plans, setPlans] = useState<Plan[]>([])
  const [show, setShow] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(false)
  const [output, setOutput] = useState<{ batchId: string; cards: string[] } | null>(null)
  const [form, setForm] = useState({ product_id: '', plan_id: '', kind: 'license', quantity: 100, prefix: '', note: '', custom_days: '' })
  const canManage = usePermissions().includes('cards:manage')
  const filteredPlans = plans.filter((p) => !form.product_id || p.product_id === form.product_id)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await get<{ items: Batch[]; total: number }>(`/admin/v1/batches${qs({ limit: 50, offset })}`)
      setItems(r.items || []); setTotal(r.total)
    } catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
  }, [offset])
  useEffect(() => { void load() }, [load])
  useEffect(() => {
    get<{ items: Product[] }>('/admin/v1/products').then((r) => setProducts(r.items)).catch((e) => setErr((e as Error).message))
    get<{ items: Plan[] }>('/admin/v1/plans').then((r) => setPlans(r.items)).catch((e) => setErr((e as Error).message))
  }, [])

  const create = async () => {
    if (busy) return
    setBusy(true)
    setErr('')
    try {
      const payload: Record<string, unknown> = {
        product_id: form.product_id,
        kind: form.kind,
        quantity: Number(form.quantity),
        prefix: form.prefix,
        note: form.note,
      }
      if (form.plan_id === '__custom__') {
        const days = Number(form.custom_days)
        if (!Number.isInteger(days) || days < 1 || days > 36500) throw new Error('自定义时长必须是 1-36500 之间的整数天数')
        payload.duration_days = days
      } else {
        if (!form.plan_id) throw new Error('请选择套餐')
        payload.plan_id = form.plan_id
      }
      if (!Number.isInteger(payload.quantity as number) || (payload.quantity as number) < 1 || (payload.quantity as number) > 100000) throw new Error('生成数量必须是 1-100000 之间的整数')
      const r = await post<{ batch: Batch; cards: string[] }>('/admin/v1/batches', payload)
      setShow(false)
      setOutput({ batchId: r.batch.id, cards: r.cards })
      load()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const downloadCsv = () => {
    if (!output) return
    const blob = new Blob([output.cards.join('\r\n')], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `cards-${output.batchId}.csv`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  const planCode = (id: string) => plans.find((p) => p.id === id)?.code || id.slice(0, 8)
  const prodCode = (id: string) => products.find((p) => p.id === id)?.code || id.slice(0, 8)
  const planLabel = (p: Plan) => `${p.name} · ${p.kind === 'duration' ? `${p.duration_days}天` : p.kind === 'fixed' ? `固定期${p.fixed_expiry_days}天` : p.kind === 'uses' ? `${p.uses_total}次` : p.kind === 'permanent' ? '永久' : '套餐信息缺失'} · ${(p.price_cents / 100).toFixed(2)}元`

  return (
    <>
      <h2 className="page-title">制作卡密</h2>
      <div className="panel intro-panel"><strong>怎么制作卡密？</strong><p className="muted">选择一个套餐，系统会按这个套餐制作卡密。例如选择“月卡”，用户激活后就能使用 30 天。一次制作的多张卡会归在一条“制卡记录”中，方便以后查询。</p></div>
      <div className="panel">
        <div className="toolbar">
          <button onClick={() => setShow(true)} disabled={!canManage || busy || loading}>制作卡密</button>
          <span className="muted">明文卡密只显示一次，请生成后立即下载保存</span>
          {(() => {
            const p = plans.find((x) => x.id === form.plan_id)
            if (!p || !p.price_cents) return null
            const cost = ((p.price_cents * Number(form.quantity)) / 100).toFixed(2)
            return <span className="badge info">合计扣款 {cost} 元（{p.price_cents / 100} 元/张 × {form.quantity}）</span>
          })()}
        </div>
        {err && <div className="error-text">{err}</div>}
        <div className="table-wrap"><table>
          <thead>
            <tr><th>记录编号</th><th>产品</th><th>套餐</th><th>生成数量</th><th>卡密前缀</th><th>备注</th><th>创建时间</th></tr>
          </thead>
          <tbody>
            {items.map((b) => (
              <tr key={b.id}>
                <td className="mono">{b.id.slice(0, 8)}…</td>
                <td className="mono">{prodCode(b.product_id)}</td>
                <td>{plans.find((p) => p.id === b.plan_id) ? planLabel(plans.find((p) => p.id === b.plan_id)!) : planCode(b.plan_id)}</td>
                <td>{b.quantity}</td>
                <td className="mono">{b.prefix}</td>
                <td className="muted">{b.note || '—'}</td>
                <td className="muted">{fmtTime(b.created_at)}</td>
              </tr>
            ))}
            {loading ? <tr><td colSpan={7} className="muted">加载中…</td></tr> : items.length === 0 && <tr><td colSpan={7} className="muted">暂无批次</td></tr>}
          </tbody>
        </table></div>
        <Pager total={total} limit={50} offset={offset} onPage={setOffset} />
      </div>
      {show && (
        <Modal title="批量制卡" onClose={() => setShow(false)}>
          <div className="form-grid">
            <Field label="产品">
              <select value={form.product_id} onChange={(e) => setForm({ ...form, product_id: e.target.value, plan_id: '' })}>
                <option value="">选择产品…</option>
                {products.map((p) => <option key={p.id} value={p.id}>{p.code} · {p.name}</option>)}
              </select>
            </Field>
            <Field label="套餐">
              <select value={form.plan_id} onChange={(e) => setForm({ ...form, plan_id: e.target.value })}>
                <option value="">选择套餐…</option>
                {filteredPlans.map((p) => <option key={p.id} value={p.id}>{planLabel(p)}</option>)}
                <option value="__custom__">自定义时长（直接填天数）</option>
              </select>
            </Field>
            {form.plan_id === '__custom__' && (
              <Field label="自定义时长（天）">
                <input type="number" min="1" value={form.custom_days} onChange={(e) => setForm({ ...form, custom_days: e.target.value })} placeholder="如 15" />
              </Field>
            )}
            <Field label="自定义前缀（可选，1-8位大写字母或2-9数字）">
              <input value={form.prefix} maxLength={8} onChange={(e) => setForm({ ...form, prefix: e.target.value.toUpperCase().replace(/[^A-Z2-9]/g, '') })} placeholder="例如 VIP、TEST" />
            </Field>
            <Field label="卡类型">
              <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
                <option value="license">授权卡</option>
                <option value="renewal">续费卡</option>
              </select>
            </Field>
            <Field label="数量（1–100000）">
              <input type="number" value={form.quantity} onChange={(e) => setForm({ ...form, quantity: +e.target.value })} />
            </Field>
            <Field label="备注" full>
              <input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
            </Field>
          </div>
          <div className="actions">
            <button className="ghost" onClick={() => setShow(false)}>取消</button>
            <button className="danger" onClick={create} disabled={busy || !form.product_id || !form.plan_id}>
              {busy ? '生成中…' : '生成（高危操作，将被审计）'}
            </button>
          </div>
        </Modal>
      )}
      {output && (
        <Modal title="明文卡密（仅本次可见，关闭后无法找回）" onClose={() => setOutput(null)}>
          <div className="cards-output">{output.cards.join('\n')}</div>
          <div className="actions">
            <button className="ghost" onClick={downloadCsv}>下载 CSV</button>
            <button onClick={() => navigator.clipboard.writeText(output.cards.join('\n'))}>复制全部</button>
            <button className="danger" onClick={() => setOutput(null)}>我已保存，关闭</button>
          </div>
        </Modal>
      )}
    </>
  )
}
