import { useEffect, useState } from 'react'
import { Routes, Route, NavLink, Navigate, useNavigate, useLocation } from 'react-router-dom'
import { get, post, setCsrf } from './api'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Products from './pages/Products'
import Plans from './pages/Plans'
import Batches from './pages/Batches'
import Cards from './pages/Cards'
import Licenses from './pages/Licenses'
import LicenseDetail from './pages/LicenseDetail'
import Agents from './pages/Agents'
import Admins from './pages/Admins'
import Audit from './pages/Audit'
import Risk from './pages/Risk'
import Keys from './pages/Keys'
import Users from './pages/Users'
import Release from './pages/Release'
import Limits from './pages/Limits'
import SecuritySettings from './pages/SecuritySettings'
import { PermissionContext } from './auth'
import { ROLE_CN } from './components'

export interface AdminInfo {
  id: string
  username: string
  display_name: string
  role: string
  mfa_enabled: boolean
  must_change_password: boolean
}

interface Me {
  admin: AdminInfo
  permissions: string[]
  balance_cents?: number
}

export function can(permissions: string[], permission: string): boolean {
  return permissions.includes(permission)
}

function Forbidden() {
  return <div className="panel"><h3>没有权限</h3><p className="muted">当前账户没有访问此页面的权限。</p></div>
}

function RequirePermission({ me, permission, children }: { me: Me; permission: string; children: React.ReactNode }) {
  return can(me.permissions, permission) ? <>{children}</> : <Forbidden />
}

export function useMe() {
  const [me, setMe] = useState<Me | null>(null)
  const [loading, setLoading] = useState(true)
  const refresh = () => {
    setLoading(true)
    get<Me>('/admin/v1/auth/me')
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setLoading(false))
  }
  useEffect(() => {
    refresh()
    const onUnauthorized = () => setMe(null)
    window.addEventListener('vft:unauthorized', onUnauthorized)
    return () => window.removeEventListener('vft:unauthorized', onUnauthorized)
  }, [])
  return { me, loading, refresh }
}

interface NavGroup { label: string; items: { to: string; label: string; perm: string }[] }
const NAV_GROUPS: NavGroup[] = [
  { label: '', items: [
    { to: '/', label: '仪表盘', perm: '' },
  ]},
  { label: '卡密业务', items: [
    { to: '/products', label: '产品管理', perm: 'products:read' },
    { to: '/plans', label: '套餐管理', perm: 'products:read' },
    { to: '/batches', label: '制作卡密', perm: 'cards:read' },
    { to: '/cards', label: '卡密管理', perm: 'cards:read' },
  ]},
  { label: '授权状态', items: [
    { to: '/licenses', label: '已激活授权', perm: 'licenses:read' },
  ]},
  { label: '用户与渠道', items: [
    { to: '/users', label: '用户管理', perm: 'users:manage' },
    { to: '/agents', label: '代理商', perm: 'agents:manage' },
    { to: '/admins', label: '管理员', perm: 'admins:manage' },
  ]},
  { label: '安全运营', items: [
    { to: '/risk', label: '风控与封禁', perm: 'risk:manage' },
    { to: '/audit', label: '审计日志', perm: 'audit:read' },
    { to: '/limits', label: '接口限流', perm: 'risk:manage' },
  ]},
  { label: '账户安全', items: [
    { to: '/security', label: '安全设置', perm: '' },
  ]},
  { label: '运营工具', items: [
    { to: '/release', label: '公告与版本', perm: 'products:read' },
    { to: '/keys', label: '密钥状态', perm: 'stats:read' },
  ]},
]

function Shell({ me, children }: { me: Me; children: React.ReactNode }) {
  const nav = useNavigate()
  const { pathname } = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  useEffect(() => { setSidebarOpen(false) }, [pathname])
  const navItems = NAV_GROUPS.flatMap((g) => g.items)
  const current =
    navItems.find((n) => n.to === pathname) ||
    navItems.find((n) => n.to !== '/' && pathname.startsWith(n.to))
  const currentGroup = current ? NAV_GROUPS.find((g) => g.items.includes(current)) : undefined
  const crumb = current ? (currentGroup?.label ? `${currentGroup.label} / ${current.label}` : current.label) : '仪表盘'
  const logout = async () => {
    await post('/admin/v1/auth/logout')
    nav('/login')
  }
  return (
    <div className="layout">
      <div
        className={`drawer-mask${sidebarOpen ? ' show' : ''}`}
        onClick={() => setSidebarOpen(false)}
      />
      <aside className={`sidebar${sidebarOpen ? ' open' : ''}`}>
        <div className="logo"><span className="logo-mark">◆</span> Lumistar</div>
        {NAV_GROUPS.map((g) => {
          const visible = g.items.filter((n) => !n.perm || me.permissions.includes(n.perm))
          if (visible.length === 0) return null
          return (
            <div key={g.label || 'main'}>
              {g.label && <div className="nav-group-label">{g.label}</div>}
              {visible.map((n) => (
                <NavLink key={n.to} to={n.to} end={n.to === '/'}>
                  {n.label}
                </NavLink>
              ))}
            </div>
          )
        })}
        <div className="spacer" />
        <div className="side-user">
          <div className="side-user-name">{me.admin.display_name}</div>
          <div className="side-user-role">{ROLE_CN[me.admin.role] || me.admin.role}</div>
          {me.balance_cents !== undefined && (
            <div className="side-user-balance">余额 {(me.balance_cents / 100).toFixed(2)} 元</div>
          )}
        </div>
      </aside>
      <div className="layout-main">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="ghost menu-btn"
              aria-label="打开导航菜单"
              onClick={() => setSidebarOpen((v) => !v)}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M2 3.5h12M2 8h12M2 12.5h12" /></svg>
            </button>
            <div className="topbar-title">{crumb}</div>
          </div>
          <div className="topbar-user">
            <span className="topbar-name">{me.admin.display_name}</span>
            <span className="badge info">{ROLE_CN[me.admin.role] || me.admin.role}</span>
            <button className="ghost small" onClick={logout}>退出登录</button>
          </div>
        </header>
        <main className="main"><PermissionContext.Provider value={me.permissions}>{children}</PermissionContext.Provider></main>
      </div>
    </div>
  )
}


// 强制改密页：must_change_password 的账户在改密前无法使用任何功能
function MustChangePassword({ onDone }: { onDone: () => void }) {
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [newPw2, setNewPw2] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (newPw !== newPw2) {
      setErr('两次输入的新口令不一致')
      return
    }
    setErr('')
    setBusy(true)
    try {
      // 改密会吊销旧会话并签发新会话——必须保存新的 CSRF token，否则后续写操作全部 403
      const res = await post<{ csrf_token: string }>('/admin/v1/auth/password', {
        old_password: oldPw,
        new_password: newPw,
      })
      if (res.csrf_token) setCsrf(res.csrf_token)
      onDone()
    } catch (ex) {
      setErr((ex as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <h1><span className="logo-mark">◆</span> Lumistar</h1>
        <div className="sub">安全要求：首次登录必须修改初始口令</div>
        <div className="field">
          <label>当前口令</label>
          <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
        </div>
        <div className="field">
          <label>新口令（≥12 字符）</label>
          <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
        </div>
        <div className="field">
          <label>确认新口令</label>
          <input type="password" value={newPw2} onChange={(e) => setNewPw2(e.target.value)} />
        </div>
        {err && <div className="error-text">{err}</div>}
        <button type="submit" disabled={busy || !oldPw || newPw.length < 12}>
          {busy ? '提交中…' : '修改口令并继续'}
        </button>
      </form>
    </div>
  )
}

export default function App() {
  const { me, loading, refresh } = useMe()
  if (loading) return <div className="login-wrap">加载中…</div>
  if (!me)
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  if (me.admin.must_change_password)
    return <MustChangePassword onDone={refresh} />
  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route
        path="*"
        element={
          <Shell me={me}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/products" element={<RequirePermission me={me} permission="products:read"><Products /></RequirePermission>} />
              <Route path="/plans" element={<RequirePermission me={me} permission="products:read"><Plans /></RequirePermission>} />
              <Route path="/batches" element={<RequirePermission me={me} permission="cards:read"><Batches /></RequirePermission>} />
              <Route path="/cards" element={<RequirePermission me={me} permission="cards:read"><Cards /></RequirePermission>} />
              <Route path="/licenses" element={<RequirePermission me={me} permission="licenses:read"><Licenses /></RequirePermission>} />
              <Route path="/licenses/:id" element={<RequirePermission me={me} permission="licenses:read"><LicenseDetail /></RequirePermission>} />
              <Route path="/agents" element={<RequirePermission me={me} permission="agents:manage"><Agents /></RequirePermission>} />
              <Route path="/admins" element={<RequirePermission me={me} permission="admins:manage"><Admins /></RequirePermission>} />
              <Route path="/risk" element={<RequirePermission me={me} permission="risk:manage"><Risk /></RequirePermission>} />
              <Route path="/audit" element={<RequirePermission me={me} permission="audit:read"><Audit /></RequirePermission>} />
              <Route path="/users" element={<RequirePermission me={me} permission="users:manage"><Users /></RequirePermission>} />
              <Route path="/release" element={<RequirePermission me={me} permission="products:read"><Release /></RequirePermission>} />
              <Route path="/limits" element={<RequirePermission me={me} permission="risk:manage"><Limits /></RequirePermission>} />
              <Route path="/keys" element={<RequirePermission me={me} permission="stats:read"><Keys /></RequirePermission>} />
              <Route path="/security" element={<RequirePermission me={me} permission="stats:read"><SecuritySettings /></RequirePermission>} />
              <Route path="*" element={<div className="panel">页面不存在</div>} />
            </Routes>
          </Shell>
        }
      />
    </Routes>
  )
}
