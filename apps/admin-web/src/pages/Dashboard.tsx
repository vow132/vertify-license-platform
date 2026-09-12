import { useEffect, useState } from 'react'
import { get } from '../api'
import { DonutChart, TrendBarChart } from '../components/charts'
import { IconAlert, IconCard, IconCardCheck, IconDevice, IconLayers, IconShield, IconTrend, IconUsers } from '../components/icons'

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
  const stats: { label: string; value: string | number; cls?: string; icon: React.ReactNode }[] = [
    { label: '当前在线设备', value: st.online_now, cls: 'ok', icon: <IconDevice /> },
    { label: '有效许可证', value: st.active_licenses, icon: <IconShield /> },
    { label: '7 日激活', value: st.activations_7d, cls: 'accent', icon: <IconTrend /> },
    { label: '未使用卡密', value: cards.unused || 0, icon: <IconCard /> },
    { label: '已激活卡密', value: cards.active || 0, icon: <IconCardCheck /> },
    { label: '24h 风险事件', value: st.risk_events_24h, cls: 'err', icon: <IconAlert /> },
    { label: '产品 / 套餐', value: `${st.products} / ${st.plans}`, icon: <IconLayers /> },
    { label: '代理商', value: st.agents, icon: <IconUsers /> },
  ]
  return (
    <>
      <h2 className="page-title">仪表盘</h2>
      <div className="stats">
        {stats.map((s) => (
          <div className="stat" key={s.label}>
            <div className="stat-head">
              <span className="stat-icon">{s.icon}</span>
              <span className="stat-label">{s.label}</span>
            </div>
            <div className={`num ${s.cls || ''}`}>{s.value}</div>
          </div>
        ))}
      </div>
      <div className="charts-grid">
        <div className="panel">
          <h3 className="panel-title">近 7 日激活趋势</h3>
          <TrendBarChart data={st.trend || []} />
        </div>
        <div className="panel">
          <h3 className="panel-title">卡密状态分布</h3>
          <DonutChart data={cards} />
        </div>
      </div>
    </>
  )
}
