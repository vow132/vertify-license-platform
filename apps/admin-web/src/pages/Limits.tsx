import { useCallback, useEffect, useState } from 'react'
import { get, post } from '../api'

interface LimitsData {
  scopes: string[]
  config: Record<string, number>
  defaults: Record<string, number>
}

const SCOPE_NAMES: Record<string, string> = {
  bootstrap: '引导接口',
  activate: '卡密激活',
  heartbeat: '心跳',
  redeem: '卡密兑换',
  user_login: '用户登录',
  user_register: '用户注册',
  user_ops: '用户操作（绑卡/改密/找回）',
}

// 接口限流：后台可配置每个开放接口 xx 次/分钟（30s 内生效）
export default function Limits() {
  const [data, setData] = useState<LimitsData | null>(null)
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [err, setErr] = useState('')
  const [saved, setSaved] = useState('')

  const load = useCallback(() => {
    get<LimitsData>('/admin/v1/ratelimits').then((d) => {
      setData(d)
      setDraft((prev) => {
        const next = { ...prev }
        for (const s of d.scopes) {
          if (next[s] === undefined) next[s] = String(d.config[s] ?? d.defaults[s] ?? '')
        }
        return next
      })
    }).catch((e) => setErr(e.message))
  }, [])
  useEffect(load, [load])

  const save = async (scope: string) => {
    setErr('')
    setSaved('')
    try {
      await post('/admin/v1/ratelimits', { scope, limit_per_min: Number(draft[scope]) })
      setSaved(scope)
      setTimeout(() => setSaved(''), 2500)
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  if (err && !data) return <div className="panel error-text">{err}</div>
  if (!data) return <div className="panel muted">加载中…</div>

  return (
    <>
      <h2 className="page-title">接口限流</h2>
      <div className="panel">
        <p className="muted" style={{ marginTop: 0 }}>
          每个开放接口按「IP + 每分钟次数」限流，保存后 30 秒内生效。未配置的接口使用环境变量默认值。
        </p>
        {err && <div className="error-text">{err}</div>}
        <table>
          <thead><tr><th>接口</th><th>当前配置（次/分钟）</th><th>默认值</th><th>操作</th></tr></thead>
          <tbody>
            {data.scopes.map((s) => (
              <tr key={s}>
                <td>{SCOPE_NAMES[s] || s} <span className="mono muted">({s})</span></td>
                <td>
                  <input type="number" min="1" style={{ width: 120 }} value={draft[s] ?? ''}
                    onChange={(e) => setDraft({ ...draft, [s]: e.target.value })} />
                </td>
                <td className="muted">{data.defaults[s] ?? '—'}</td>
                <td>
                  <button className="small" disabled={Number(draft[s]) < 1 || String(data.config[s] ?? '') === draft[s]}
                    onClick={() => save(s)}>保存</button>
                  {saved === s && <span className="ok-text" style={{ marginLeft: 8 }}>已保存</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
