import { useEffect, useState } from 'react'
import { get } from '../api'
import { DonutChart, TrendBarChart } from '../components/charts'

interface Stats {
  products: number
  plans: number
  cards_by_status: Record<string, number>
  active_licenses: number
  online_now: number
  activations_7d: number
  risk_events_24h: number
  agents: number
  trend: { day: string; count: number }[]
}

export default function Dashboard() {
  const [st, setSt] = useState<Stats | null>(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    get<Stats>('/admin/v1/stats').then(setSt).catch((e) => setErr(e.message))
  }, [])
  if (err) return <div className="panel error-text">{err}</div>
  if (!st) return <div className="panel muted">加载中…</div>
  const cards = st.cards_by_status || {}
  return (
    <>
      <h2 className="page-title">仪表盘</h2>
      <div className="stats">
        <div className="stat glass"><div className="num ok">{st.online_now}</div><div className="label">当前在线设备</div></div>
        <div className="stat glass"><div className="num">{st.active_licenses}</div><div className="label">有效许可证</div></div>
        <div className="stat glass"><div className="num accent">{st.activations_7d}</div><div className="label">7 日激活</div></div>
        <div className="stat glass"><div className="num">{cards.unused || 0}</div><div className="label">未使用卡密</div></div>
        <div className="stat glass"><div className="num">{cards.active || 0}</div><div className="label">已激活卡密</div></div>
        <div className="stat glass"><div className="num err">{st.risk_events_24h}</div><div className="label">24h 风险事件</div></div>
        <div className="stat glass"><div className="num">{st.products} / {st.plans}</div><div className="label">产品 / 套餐</div></div>
        <div className="stat glass"><div className="num">{st.agents}</div><div className="label">代理商</div></div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="panel glass-panel">
          <h3 style={{ marginTop: 0, fontWeight: 650, fontSize: 14 }}>近 7 日激活趋势</h3>
          <TrendBarChart data={st.trend || []} />
        </div>
        <div className="panel glass-panel">
          <h3 style={{ marginTop: 0, fontWeight: 650, fontSize: 14 }}>卡密状态分布</h3>
          <DonutChart data={cards} />
        </div>
      </div>
    </>
  )
}
