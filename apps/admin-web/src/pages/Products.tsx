import { useCallback, useEffect, useState } from 'react'
import { get, post } from '../api'
import { Badge, Field, Modal, fmtTime } from '../components'

interface Product {
  id: string
  code: string
  name: string
  status: string
  created_at: string
}

export default function Products() {
  const [items, setItems] = useState<Product[]>([])
  const [show, setShow] = useState(false)
  const [name, setName] = useState('')
  const [err, setErr] = useState('')

  const load = useCallback(() => {
    get<{ items: Product[] }>('/admin/v1/products').then((r) => setItems(r.items)).catch((e) => setErr(e.message))
  }, [])
  useEffect(load, [load])

  const create = async () => {
    try {
      await post('/admin/v1/products', { name })
      setShow(false)
      setName('')
      load()
    } catch (e) {
      setErr((e as Error).message)
    }
  }
  const setStatus = async (id: string, status: string) => {
    await post(`/admin/v1/products/${id}/status`, { status })
    load()
  }

  return (
    <>
      <h2 className="page-title">产品</h2>
      <div className="panel">
        <div className="toolbar">
          <button onClick={() => setShow(true)}>新建产品</button>
        </div>
        {err && <div className="error-text">{err}</div>}
        <table>
          <thead>
            <tr><th>代码</th><th>名称</th><th>状态</th><th>创建时间</th><th>操作</th></tr>
          </thead>
          <tbody>
            {items.map((p) => (
              <tr key={p.id}>
                <td className="mono">{p.code}</td>
                <td>{p.name}</td>
                <td><Badge status={p.status} /></td>
                <td className="muted">{fmtTime(p.created_at)}</td>
                <td>
                  {p.status === 'active' ? (
                    <button className="warn small" onClick={() => setStatus(p.id, 'retired')}>退役</button>
                  ) : (
                    <button className="small" onClick={() => setStatus(p.id, 'active')}>启用</button>
                  )}
                </td>
              </tr>
            ))}
            {items.length === 0 && <tr><td colSpan={5} className="muted">暂无产品</td></tr>}
          </tbody>
        </table>
      </div>
      {show && (
        <Modal title="新建产品" onClose={() => setShow(false)}>
          <div className="form-grid">
            <Field label="产品名称" full>
              <input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
            </Field>
            <div className="full muted" style={{ marginBottom: 8 }}>产品代码创建后自动生成，无需填写</div>
          </div>
          <div className="actions">
            <button className="ghost" onClick={() => setShow(false)}>取消</button>
            <button onClick={create} disabled={!name}>创建</button>
          </div>
        </Modal>
      )}
    </>
  )
}
