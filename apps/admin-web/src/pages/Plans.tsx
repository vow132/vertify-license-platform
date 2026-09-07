import { useCallback, useEffect, useState } from 'react'
import { del, get, post, put } from '../api'
import { Badge, Field, Modal } from '../components'
import { usePermissions } from '../auth'

interface Plan {
  id: string; product_id: string; code: string; name: string; kind: string
  duration_days: number; fixed_expiry_days: number; uses_total: number
  device_limit: number; concurrent_limit: number; features: string[]
  offline_grace_seconds: number; heartbeat_interval_seconds: number; lease_ttl_seconds: number
  rebind_cooldown_hours: number; monthly_rebind_limit: number; min_client_version?: string
  price_cents: number; status: string; created_at: string
}
interface Product { id: string; code: string; name: string }
type PlanForm = Omit<Plan, 'id' | 'price_cents' | 'status' | 'created_at' | 'features'> & { price_yuan: string; features: string }

const emptyForm: PlanForm = {
  product_id: '', code: '', name: '', kind: 'duration', duration_days: 30,
  fixed_expiry_days: 30, uses_total: 1, device_limit: 1, concurrent_limit: 1,
  features: '', offline_grace_seconds: 0, heartbeat_interval_seconds: 60,
  lease_ttl_seconds: 300, rebind_cooldown_hours: 24, monthly_rebind_limit: 2,
  min_client_version: '', price_yuan: '0',
}

export default function Plans() {
  const [items, setItems] = useState<Plan[]>([])
  const [products, setProducts] = useState<Product[]>([])
  const [show, setShow] = useState(false)
  const [editing, setEditing] = useState<Plan | null>(null)
  const [detail, setDetail] = useState<Plan | null>(null)
  const [err, setErr] = useState('')
  const [form, setForm] = useState<PlanForm>(emptyForm)
  const permissions = usePermissions()
  const canWrite = permissions.includes('products:write')

  const load = useCallback(() => {
    setErr('')
    get<{ items: Plan[] }>('/admin/v1/plans').then((r) => setItems(r.items || [])).catch((e) => setErr(e.message))
    get<{ items: Product[] }>('/admin/v1/products').then((r) => setProducts(r.items || [])).catch((e) => setErr(e.message))
  }, [])
  useEffect(load, [load])

  const toPayload = () => ({
    ...form,
    features: form.features.split(',').map((s) => s.trim()).filter(Boolean),
    price_cents: Math.round(Number(form.price_yuan) * 100),
    duration_days: Number(form.duration_days), fixed_expiry_days: Number(form.fixed_expiry_days),
    uses_total: Number(form.uses_total), device_limit: Number(form.device_limit),
    concurrent_limit: Number(form.concurrent_limit), offline_grace_seconds: Number(form.offline_grace_seconds),
    heartbeat_interval_seconds: Number(form.heartbeat_interval_seconds), lease_ttl_seconds: Number(form.lease_ttl_seconds),
    rebind_cooldown_hours: Number(form.rebind_cooldown_hours), monthly_rebind_limit: Number(form.monthly_rebind_limit),
  })
  const save = async () => {
    try {
      const payload = toPayload()
      if (!form.name.trim() || !form.product_id || !form.code.trim() || !Number.isFinite(payload.price_cents) || payload.price_cents < 0) throw new Error('请完整填写套餐名称、代码和合法价格')
      if (editing) await put(`/admin/v1/plans/${editing.id}`, payload)
      else await post('/admin/v1/plans', payload)
      setShow(false); setEditing(null); setForm(emptyForm); load()
    } catch (e) { setErr((e as Error).message) }
  }
  const openEdit = (p: Plan) => {
    setEditing(p)
    setForm({ product_id: p.product_id, code: p.code, name: p.name, kind: p.kind, duration_days: p.duration_days, fixed_expiry_days: p.fixed_expiry_days, uses_total: p.uses_total, device_limit: p.device_limit, concurrent_limit: p.concurrent_limit, features: (p.features || []).join(', '), offline_grace_seconds: p.offline_grace_seconds, heartbeat_interval_seconds: p.heartbeat_interval_seconds, lease_ttl_seconds: p.lease_ttl_seconds, rebind_cooldown_hours: p.rebind_cooldown_hours, monthly_rebind_limit: p.monthly_rebind_limit, min_client_version: p.min_client_version || '', price_yuan: (p.price_cents / 100).toFixed(2) })
    setShow(true)
  }
  const setStatus = async (id: string, status: string) => { try { await post(`/admin/v1/plans/${id}/status`, { status }); load() } catch (e) { setErr((e as Error).message) } }
  const remove = async (p: Plan) => { if (!confirm(`确定删除套餐“${p.name}”吗？已使用套餐只能退役。`)) return; try { await del(`/admin/v1/plans/${p.id}`); load() } catch (e) { setErr((e as Error).message) } }
  const prodCode = (id: string) => products.find((p) => p.id === id)?.code || id
  const duration = (p: Plan) => p.kind === 'duration' ? `${p.duration_days}天` : p.kind === 'fixed' ? `固定期 ${p.fixed_expiry_days}天` : p.kind === 'uses' ? `${p.uses_total}次` : '永久'

  return <>
    <h2 className="page-title">套餐管理</h2>
    <div className="panel intro-panel"><strong>套餐就是你卖给用户的商品。</strong><p className="muted">例如“月卡 · 30天 · 19.90元”。你可以自己新增、修改、退役和删除套餐；产品、代码和类型创建后不能修改，避免已经卖出的卡密含义发生变化。</p></div>
    {err && <div className="error-text">{err}</div>}
    <div className="panel">
      <div className="toolbar">{canWrite && <button onClick={() => { setEditing(null); setForm(emptyForm); setShow(true) }}>新增套餐</button>}<span className="muted">价格、时长和功能都可以自己设置</span></div>
      <div className="table-wrap"><table><thead><tr><th>代码</th><th>产品</th><th>名称</th><th>类型/时长</th><th>设备/并发</th><th>价格</th><th>功能</th><th>状态</th><th>操作</th></tr></thead><tbody>
        {items.map((p) => <tr key={p.id}><td className="mono">{p.code}</td><td>{prodCode(p.product_id)}</td><td>{p.name}</td><td>{duration(p)}</td><td>{p.device_limit} 台 / {p.concurrent_limit} 并发</td><td>{(p.price_cents / 100).toFixed(2)} 元</td><td className="mono">{(p.features || []).join(', ') || '—'}</td><td><Badge status={p.status} /></td><td><button className="small" onClick={() => setDetail(p)}>详情</button> {canWrite && <><button className="small" onClick={() => openEdit(p)}>编辑</button> <button className={p.status === 'active' ? 'warn small' : 'small'} onClick={() => setStatus(p.id, p.status === 'active' ? 'retired' : 'active')}>{p.status === 'active' ? '退役' : '启用'}</button> <button className="danger small" onClick={() => remove(p)}>删除</button></>}</td></tr>)}
        {items.length === 0 && <tr><td colSpan={9} className="muted">暂无套餐</td></tr>}
      </tbody></table></div>
    </div>
    {detail && <Modal title={`套餐详情：${detail.name}`} onClose={() => setDetail(null)}><div className="kv"><div className="k">代码</div><div className="mono">{detail.code}</div><div className="k">产品</div><div>{prodCode(detail.product_id)}</div><div className="k">类型/时长</div><div>{duration(detail)}</div><div className="k">价格</div><div>{(detail.price_cents / 100).toFixed(2)} 元</div><div className="k">设备/并发</div><div>{detail.device_limit} / {detail.concurrent_limit}</div><div className="k">心跳/租约</div><div>{detail.heartbeat_interval_seconds}s / {detail.lease_ttl_seconds}s</div><div className="k">离线宽限</div><div>{detail.offline_grace_seconds}s</div><div className="k">功能</div><div>{(detail.features || []).join(', ') || '—'}</div></div></Modal>}
    {show && <Modal title={editing ? '编辑套餐' : '新增套餐'} onClose={() => { setShow(false); setEditing(null) }}><div className="form-grid"><Field label="产品"><select disabled={!!editing} value={form.product_id} onChange={(e) => setForm({ ...form, product_id: e.target.value })}><option value="">选择产品…</option>{products.map((p) => <option key={p.id} value={p.id}>{p.code} · {p.name}</option>)}</select></Field><Field label="套餐代码"><input disabled={!!editing} value={form.code} onChange={(e) => setForm({ ...form, code: e.target.value.toLowerCase() })} /></Field><Field label="名称"><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field><Field label="类型"><select disabled={!!editing} value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}><option value="duration">时长卡</option><option value="fixed">固定期卡</option><option value="uses">次卡</option><option value="permanent">永久卡</option></select></Field>{form.kind === 'duration' && <Field label="使用时长（天）"><input type="number" min="1" value={form.duration_days} onChange={(e) => setForm({ ...form, duration_days: +e.target.value })} /></Field>}{form.kind === 'fixed' && <Field label="固定有效期（天）"><input type="number" min="1" value={form.fixed_expiry_days} onChange={(e) => setForm({ ...form, fixed_expiry_days: +e.target.value })} /></Field>}{form.kind === 'uses' && <Field label="使用次数"><input type="number" min="1" value={form.uses_total} onChange={(e) => setForm({ ...form, uses_total: +e.target.value })} /></Field>}<Field label="价格（元）"><input type="number" min="0" step="0.01" value={form.price_yuan} onChange={(e) => setForm({ ...form, price_yuan: e.target.value })} /></Field><Field label="设备上限"><input type="number" min="1" value={form.device_limit} onChange={(e) => setForm({ ...form, device_limit: +e.target.value })} /></Field><Field label="并发上限"><input type="number" min="1" value={form.concurrent_limit} onChange={(e) => setForm({ ...form, concurrent_limit: +e.target.value })} /></Field><Field label="心跳间隔（秒）"><input type="number" min="10" value={form.heartbeat_interval_seconds} onChange={(e) => setForm({ ...form, heartbeat_interval_seconds: +e.target.value })} /></Field><Field label="租约时长（秒）"><input type="number" min="60" value={form.lease_ttl_seconds} onChange={(e) => setForm({ ...form, lease_ttl_seconds: +e.target.value })} /></Field><Field label="离线宽限（秒）"><input type="number" min="0" value={form.offline_grace_seconds} onChange={(e) => setForm({ ...form, offline_grace_seconds: +e.target.value })} /></Field><Field label="功能列表（逗号分隔）" full><input value={form.features} onChange={(e) => setForm({ ...form, features: e.target.value })} placeholder="aimbot, esp" /></Field></div><div className="actions"><button className="ghost" onClick={() => setShow(false)}>取消</button><button onClick={save}>{editing ? '保存修改' : '创建套餐'}</button></div></Modal>}
  </>
}
