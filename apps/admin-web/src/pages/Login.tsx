import { useState } from 'react'
import { post } from '../api'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [needTotp, setNeedTotp] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      const res = await post<{ mfa_required: boolean; csrf_token?: string }>('/admin/v1/auth/login', {
        username,
        password,
        totp: totp || undefined,
      })
      if (res.mfa_required) {
        setNeedTotp(true)
        return
      }
      if (res.csrf_token) sessionStorage.setItem('csrf', res.csrf_token)
      window.location.href = '/'
    } catch (ex) {
      setErr((ex as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-brand">
          <div className="login-brand-logo"><span className="logo-mark">◆</span> Vertify</div>
          <div className="login-brand-title">商业级卡密验证<br />与授权管理平台</div>
          <ul className="login-brand-points">
            <li>卡密全生命周期：制卡、激活、续费、冻结、吊销</li>
            <li>机器码绑定与心跳租约，服务端秒级吊销传播</li>
            <li>应用层信封加密，抓包无明文卡密</li>
          </ul>
        </div>
        <form className="login-box" onSubmit={submit}>
          <h1><span className="logo-mark">◆</span> Vertify</h1>
          <div className="sub">许可验证平台 · 管理控制台</div>
        <div className="field">
          <label>用户名</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
        </div>
        <div className="field">
          <label>密码</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        {needTotp && (
          <div className="field">
            <label>两步验证码（TOTP）</label>
            <input value={totp} onChange={(e) => setTotp(e.target.value)} inputMode="numeric" maxLength={6} />
          </div>
        )}
        {err && <div className="error-text">{err}</div>}
        <button type="submit" disabled={busy || !username || !password}>
          {busy ? '登录中…' : needTotp ? '验证并登录' : '登录'}
        </button>
        </form>
      </div>
    </div>
  )
}
