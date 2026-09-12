// 统一笔画风格的内联 SVG 图标（16×16 视窗，stroke 1.8，round 端点）
const base = {
  width: 16,
  height: 16,
  viewBox: '0 0 16 16',
  fill: 'none' as const,
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
}

export const IconDevice = () => (
  <svg {...base}><rect x="1.5" y="2.5" width="13" height="8.5" rx="1.5" /><path d="M5.5 13.5h5M8 11v2.5" /></svg>
)
export const IconShield = () => (
  <svg {...base}><path d="M8 1.8 13.5 4v4.2c0 3.2-2.3 5.4-5.5 6.4C4.8 13.6 2.5 11.4 2.5 8.2V4L8 1.8Z" /><path d="m5.8 7.9 1.6 1.6 2.8-3" /></svg>
)
export const IconTrend = () => (
  <svg {...base}><path d="M1.8 11.5 6 7.2l2.5 2.5 5.4-5.5" /><path d="M10 4.2h4v4" /></svg>
)
export const IconCard = () => (
  <svg {...base}><rect x="1.5" y="3" width="13" height="10" rx="1.8" /><path d="M1.5 6.2h13M4.2 10.2h3" /></svg>
)
export const IconCardCheck = () => (
  <svg {...base}><rect x="1.5" y="3" width="13" height="10" rx="1.8" /><path d="M1.5 6.2h13" /><path d="m5.5 9.8 1.3 1.3 2.4-2.6" /></svg>
)
export const IconAlert = () => (
  <svg {...base}><path d="M6.9 2.4 1.6 11.8a1.3 1.3 0 0 0 1.1 2h10.6a1.3 1.3 0 0 0 1.1-2L9.1 2.4a1.3 1.3 0 0 0-2.2 0Z" /><path d="M8 6v3M8 11.4v.2" /></svg>
)
export const IconLayers = () => (
  <svg {...base}><path d="m8 1.8 6.2 3.1L8 8 1.8 4.9 8 1.8Z" /><path d="m2 8 6 3 6-3M2 11l6 3 6-3" /></svg>
)
export const IconUsers = () => (
  <svg {...base}><circle cx="5.8" cy="5.4" r="2.4" /><path d="M1.6 13.6c.5-2.4 2.2-3.7 4.2-3.7s3.7 1.3 4.2 3.7" /><path d="M10.6 3.3a2.4 2.4 0 0 1 0 4.3M11.5 10.1c1.5.4 2.6 1.6 3 3.5" /></svg>
)
