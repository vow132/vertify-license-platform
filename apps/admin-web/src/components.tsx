import { ReactNode } from 'react'

// ===== 状态 → 中文标签映射 =====
const STATUS_CN: Record<string, string> = {
  // 通用状态
  active: '正常',
  unused: '未使用',
  ok: '正常',
  frozen: '已冻结',
  suspended: '已停用',
  depleted: '已用尽',
  throttled: '已限流',
  revoked: '已吊销',
  voided: '已作废',
  banned: '已封禁',
  blocked: '已拦截',
  disabled: '已禁用',
  retired: '已退役',
  unbound: '已解绑',
  expired: '已过期',
  // 风险等级
  critical: '严重',
  high: '较高',
  medium: '中等',
  low: '较低',
  // 处置动作
  logged: '已记录',
  // 许可证事件（与通用状态不冲突的）
  activated: '激活',
  renewed: '续费',
  unfrozen: '解冻',
  device_bound: '绑定设备',
  device_unbound: '解绑设备',
  policy_updated: '策略更新',
  // 用户日志事件
  register: '注册',
  login: '登录',
  login_failed: '登录失败',
  login_machine_rejected: '机器不符',
  bind_card: '绑卡续期',
  change_pw: '修改密码',
  recover: '找回密码',
  machine_reset: '解绑机器',
  // 事件 kind
  'card.freeze': '冻结卡密',
  'card.unfreeze': '解冻卡密',
  'card.revoke': '吊销卡密',
  'card.note': '卡密备注',
  'card.void': '作废卡密',
  'license.freeze': '冻结许可',
  'license.unfreeze': '解冻许可',
  'license.revoke': '吊销许可',
  'license.void': '作废许可',
  'license.note': '许可备注',
  'license.extend': '手动续期',
  'device.unbind': '解绑设备',
  'batch.create': '批量制卡',
  'product.create': '创建产品',
  'product.status': '产品状态',
  'plan.create': '创建套餐',
  'plan.status': '套餐状态',
  'agent.create': '创建代理',
  'agent.status': '代理状态',
  'agent.balance': '调整余额',
  'admin.create': '创建管理员',
  'admin.status': '管理员状态',
  'auth.login': '登录',
  'auth.logout': '退出登录',
  'auth.mfa_enable': '启用MFA',
  'auth.mfa_disable': '关闭MFA',
  'auth.password_change': '修改密码',
  'ban.create': '新增封禁',
  'ban.delete': '解除封禁',
  'message.create': '发布公告',
  'version.create': '发布版本',
  'ratelimit.set': '限流设置',
  'user.disable': '禁用用户',
  'user.enable': '启用用户',
  'user.reset-machine': '解绑机器',
  'user.extend': '用户续期',
  // 角色
  superadmin: '超级管理员',
  admin: '管理员',
  agent: '代理商',
  auditor: '审计员',
  viewer: '只读',
  // MFA
  '已启用': '已启用',
  '未启用': '未启用',
}

export function statusLabel(s: string): string {
  return STATUS_CN[s] || s
}

export function Badge({ status }: { status: string }) {
  const cls =
    ['active', 'unused', 'ok'].includes(status) ? 'ok'
    : ['frozen', 'suspended', 'depleted', 'throttled', 'retired', 'unbound'].includes(status) ? 'warn'
    : ['revoked', 'voided', 'banned', 'blocked', 'disabled', 'critical', 'high'].includes(status) ? 'err'
    : 'info'
  return <span className={`badge ${cls}`}>{statusLabel(status)}</span>
}

export function PlainBadge({ label, tone }: { label: string; tone?: string }) {
  return <span className={`badge ${tone || ''}`}>{statusLabel(label) || label}</span>
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="modal-mask" role="presentation" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <h3>{title}</h3>
        {children}
      </div>
    </div>
  )
}

export function Pager({ total, limit, offset, onPage }: { total: number; limit: number; offset: number; onPage: (o: number) => void }) {
  return (
    <div className="pager">
      <span>共 {total} 条</span>
      <button className="ghost small" disabled={offset === 0} onClick={() => onPage(Math.max(0, offset - limit))}>
        上一页
      </button>
      <button className="ghost small" disabled={offset + limit >= total} onClick={() => onPage(offset + limit)}>
        下一页
      </button>
    </div>
  )
}

export function Field({ label, full, children }: { label: string; full?: boolean; children: ReactNode }) {
  return (
    <div className={`field ${full ? 'full' : ''}`}>
      <label>{label}</label>
      {children}
    </div>
  )
}

export function fmtTime(s?: string | null) {
  if (!s) return '—'
  const date = new Date(s)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('zh-CN', { hour12: false })
}

// ===== 通用枚举中文映射 =====
export const KIND_CN: Record<string, string> = {
  license: '授权卡',
  renewal: '续费卡',
  duration: '时长卡',
  fixed: '固定期卡',
  uses: '次卡',
  permanent: '永久卡',
  tpm: 'TPM 硬件',
  software: '软件密钥',
}

export function kindLabel(k: string): string {
  return KIND_CN[k] || k
}

export const ROLE_CN: Record<string, string> = {
  superadmin: '超级管理员',
  admin: '管理员',
  agent: '代理商',
  auditor: '审计员',
  viewer: '只读',
}

// ===== 事件类型中文映射 =====
export const EVENT_CN: Record<string, string> = {
  activated: '激活',
  renewed: '续费',
  frozen: '冻结',
  unfrozen: '解冻',
  revoked: '吊销',
  voided: '作废',
  expired: '到期',
  device_bound: '绑定设备',
  device_unbound: '解绑设备',
  policy_updated: '策略变更',
  register: '注册',
  login: '登录',
  login_failed: '登录失败',
  login_machine_rejected: '机器不符',
  bind_card: '绑卡续期',
  change_pw: '修改密码',
  recover: '找回密码',
  machine_reset: '解绑机器',
  disabled: '禁用',
}
