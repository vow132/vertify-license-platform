// 轻量 SVG 图表（无外部依赖）
import { ReactNode } from 'react'

// ===== 环形图 =====
const STATUS_COLORS: Record<string, string> = {
  active: '#2563eb', unused: '#94a3b8', frozen: '#d97706',
  revoked: '#dc2626', voided: '#7c3aed', depleted: '#6b7280',
}
const STATUS_LABELS: Record<string, string> = {
  active: '使用中', unused: '未使用', frozen: '已冻结',
  revoked: '已吊销', voided: '已作废', depleted: '已用尽',
}

export function DonutChart({ data, size = 160, thickness = 24 }: {
  data: Record<string, number>
  size?: number
  thickness?: number
}) {
  const entries = Object.entries(data).filter(([, v]) => v > 0)
  const total = entries.reduce((sum, [, v]) => sum + v, 0)
  if (total === 0) return <div className="muted" style={{ textAlign: 'center', padding: 20 }}>暂无数据</div>
  const r = (size - thickness) / 2
  const cx = size / 2
  const cy = size / 2
  const circumference = 2 * Math.PI * r
  let acc = 0
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#f1f5f9" strokeWidth={thickness} />
        {entries.map(([k, v]) => {
          const frac = v / total
          const dash = frac * circumference
          const offset = -acc * circumference
          acc += frac
          return (
            <circle key={k} cx={cx} cy={cy} r={r} fill="none"
              stroke={STATUS_COLORS[k] || '#cbd5e1'} strokeWidth={thickness}
              strokeDasharray={`${dash} ${circumference - dash}`} strokeDashoffset={offset}
              strokeLinecap="butt" />
          )
        })}
        <text x={cx} y={cy - 4} textAnchor="middle" fontSize="22" fontWeight="700" fill="#1a2233"
          transform={`rotate(90 ${cx} ${cy})`}>{total}</text>
        <text x={cx} y={cy + 16} textAnchor="middle" fontSize="11" fill="#7a8699"
          transform={`rotate(90 ${cx} ${cy})`}>总卡数</text>
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {entries.map(([k, v]) => (
          <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5 }}>
            <span style={{ width: 10, height: 10, borderRadius: 3, background: STATUS_COLORS[k] || '#cbd5e1', flexShrink: 0 }} />
            <span style={{ color: '#7a8699' }}>{STATUS_LABELS[k] || k}</span>
            <span style={{ fontWeight: 600, color: '#1a2233' }}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ===== 柱状图（近 7 日激活趋势） =====
export function TrendBarChart({ data, height = 180 }: {
  data: { day: string; count: number }[]
  height?: number
}) {
  if (!data || data.length === 0) return <div className="muted" style={{ textAlign: 'center', padding: 20 }}>暂无数据</div>
  const max = Math.max(...data.map((d) => d.count), 1)
  const barW = 36
  const gap = 14
  const chartW = data.length * (barW + gap) - gap
  const chartH = height - 30
  const dayLabel = (iso: string) => {
    const d = new Date(iso)
    return `${d.getMonth() + 1}/${d.getDate()}`
  }
  return (
    <div style={{ overflowX: 'auto' }}>
      <svg width={Math.max(chartW, 300)} height={height} style={{ display: 'block', margin: '0 auto' }}>
        <defs>
          <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#93c5fd" />
          </linearGradient>
        </defs>
        {data.map((d, i) => {
          const barH = (d.count / max) * (chartH - 20)
          const x = i * (barW + gap) + gap / 2
          const y = chartH - barH
          return (
            <g key={d.day}>
              <rect x={x} y={y} width={barW} height={Math.max(barH, 2)} rx={4} fill="url(#barGrad)" />
              {d.count > 0 && (
                <text x={x + barW / 2} y={y - 5} textAnchor="middle" fontSize="11" fontWeight="600" fill="#1a2233">
                  {d.count}
                </text>
              )}
              <text x={x + barW / 2} y={chartH + 16} textAnchor="middle" fontSize="11" fill="#7a8699">
                {dayLabel(d.day)}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

// ===== 卡片容器（毛玻璃） =====
export function GlassCard({ children, style }: { children: ReactNode; style?: React.CSSProperties }) {
  return (
    <div className="glass-card" style={style}>
      {children}
    </div>
  )
}
