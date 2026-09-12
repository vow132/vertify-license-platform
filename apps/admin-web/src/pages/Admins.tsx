import { useCallback, useEffect, useState } from 'react'
import { get, post } from '../api'
import { Badge, Field, Modal, fmtTime } from '../components'

interface Admin {
  id: string
  username: string
  display_name: string
  role: string
  status: string
  mfa_enabled: boolean
  must_change_password: boolean
  created_at: string
  last_login_at: string | null
}

export default function Admins() {
  const [items, setItems] = useState<Admin[]>([])
  const [show, setShow] = useState(false)
  const [err, setErr] = useState('')
  const [form, setForm] = useState({ username: '', display_name: '', password: '', role: 'viewer' })
  const load = useCallback(() => {
    get<{ items: Admin[] }>('/admin/v1/admins').then((r) => setItems(r.items)).catch((e) => setErr(e.message))
  }, [])
  useEffect(load, [load])

  const create = async () => {
    try {
      await post('/admin/v1/admins', form)
      setShow(false)
      setForm({ username: '', display_name: '', password: '', role: 'viewer' })
      load()
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <>
      <h2 className="page-title">管理员</h2>
      <div className="panel">
        <div className="toolbar">
          <button onClick={() => setShow(true)}>新建管理员</button>
          <span className="muted">新建账户首次登录必须改密；建议强制启用 MFA</span>
        </div>
        {err && <div className="error-text">{err}</div>}
        <div className="table-wrap"><table>
          <thead>
            <tr><th>用户名</th><th>显示名</th><th>角色</th><th>MFA</th><th>状态</th><th>最近登录</th><th>操作</th></tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.username}</td>
                <td>{a.display_name}</td>
                <td><span className="badge">{{
                  superadmin: '超级管理员', admin: '管理员', agent: '代理商',
                  auditor: '审计员', viewer: '只读',
                }[a.role] || a.role}</span></td>
                <td>{a.mfa_enabled ? <span className="badge ok">已启用</span> : <span className="badge warn">未启用</span>}</td>
                <td><Badge status={a.status} /></td>
                <td className="muted">{fmtTime(a.last_login_at)}</td>
                <td>
                  {a.status === 'active' ? (
                    <button className="danger small" onClick={async () => {
                      if (!confirm(`确认禁用 ${a.username}？其全部会话将被吊销。`)) return
                      await post(`/admin/v1/admins/${a.id}/status`, { status: 'disabled' })
                      load()
                    }}>禁用</button>
                  ) : (
                    <button className="small" onClick={async () => { await post(`/admin/v1/admins/${a.id}/status`, { status: 'active' }); load() }}>启用</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>
      {show && (
        <Modal title="新建管理员" onClose={() => setShow(false)}>
          <div className="form-grid">
            <Field label="用户名"><input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>
            <Field label="显示名"><input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
            <Field label="初始密码（≥12 字符）"><input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
            <Field label="角色">
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                <option value="admin">管理员</option>
                <option value="agent">代理商</option>
                <option value="auditor">审计员</option>
                <option value="viewer">只读</option>
              </select>
            </Field>
          </div>
          <div className="actions">
            <button className="ghost" onClick={() => setShow(false)}>取消</button>
            <button onClick={create} disabled={!form.username || !form.display_name || form.password.length < 12}>创建</button>
          </div>
        </Modal>
      )}
    </>
  )
}
