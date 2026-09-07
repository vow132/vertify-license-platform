import { useState } from 'react'
import { post } from '../api'
import { Field, Modal } from '../components'

export default function SecuritySettings() {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const beginSetup = async () => {
    setError('')
    setMessage('')
    try {
      const result = await post<{ secret: string; uri: string }>('/admin/v1/auth/mfa/setup', {})
      setSetup(result)
      setCode('')
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const enable = async () => {
    if (!/^\d{6}$/.test(code)) {
      setError('请输入 6 位动态验证码')
      return
    }
    setBusy(true)
    setError('')
    try {
      await post('/admin/v1/auth/mfa/enable', { code })
      setSetup(null)
      setCode('')
      setMessage('MFA 已启用。下次登录需要输入动态验证码。')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const disable = async () => {
    if (!password) {
      setError('请输入当前密码确认关闭 MFA')
      return
    }
    if (!confirm('关闭 MFA 会降低管理员账户安全性，确认继续吗？')) return
    setBusy(true)
    setError('')
    try {
      await post('/admin/v1/auth/mfa/disable', { password })
      setPassword('')
      setMessage('MFA 已关闭。建议尽快重新启用。')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <h2 className="page-title">安全设置</h2>
      <div className="panel intro-panel">
        <strong>管理员账户安全</strong>
        <p className="muted">MFA 是登录时的第二道验证。建议所有管理员都启用，动态验证码请使用身份验证器保存。</p>
      </div>
      {error && <div className="error-text">{error}</div>}
      {message && <div className="success-text">{message}</div>}
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>两步验证（MFA）</h3>
        <p className="muted">启用后，登录除了密码还需要 6 位动态验证码。</p>
        <div className="actions" style={{ justifyContent: 'flex-start' }}>
          <button onClick={beginSetup} disabled={busy}>开始设置 MFA</button>
        </div>
      </div>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>关闭 MFA</h3>
        <p className="muted">只有在确认设备不再使用时关闭。需要输入当前管理员密码。</p>
        <div className="form-grid">
          <Field label="当前密码">
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
        </div>
        <div className="actions" style={{ justifyContent: 'flex-start' }}>
          <button className="danger" onClick={disable} disabled={busy || !password}>关闭 MFA</button>
        </div>
      </div>
      {setup && (
        <Modal title="设置 MFA" onClose={() => setSetup(null)}>
          <p className="muted">请把下面的密钥录入身份验证器，然后输入生成的 6 位验证码完成启用。密钥只在本次设置窗口显示。</p>
          <Field label="设置密钥">
            <input className="mono" value={setup.secret} readOnly onFocus={(e) => e.currentTarget.select()} />
          </Field>
          <Field label="otpauth 地址（可复制到支持的身份验证器）">
            <textarea rows={4} value={setup.uri} readOnly onFocus={(e) => e.currentTarget.select()} />
          </Field>
          <Field label="动态验证码">
            <input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="6 位数字" />
          </Field>
          <div className="actions">
            <button className="ghost" onClick={() => setSetup(null)}>取消</button>
            <button onClick={enable} disabled={busy || code.length !== 6}>{busy ? '验证中…' : '启用 MFA'}</button>
          </div>
        </Modal>
      )}
    </>
  )
}
