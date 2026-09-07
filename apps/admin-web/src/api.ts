// API 客户端：会话 cookie + CSRF 头；错误统一解析为 {code,message}。
export class ApiError extends Error {
  code: string
  status: number
  constructor(code: string, message: string, status: number) {
    super(message)
    this.code = code
    this.status = status
  }
}

let csrfToken = sessionStorage.getItem('csrf') || ''

export function setCsrf(token: string) {
  csrfToken = token
  sessionStorage.setItem('csrf', token)
}

async function handle<T>(resp: Response): Promise<T> {
  if (resp.status === 401) {
    sessionStorage.removeItem('csrf')
    window.dispatchEvent(new Event('vft:unauthorized'))
    throw new ApiError('UNAUTHORIZED', '会话已过期，请重新登录', 401)
  }
  const text = await resp.text()
  let body: any = {}
  if (text.trim()) {
    const contentType = resp.headers.get('content-type') || ''
    if (contentType.includes('application/json')) {
      try {
        body = JSON.parse(text)
      } catch {
        throw new ApiError('INVALID_RESPONSE', '服务器返回了无效数据，请稍后重试', resp.status)
      }
    } else {
      throw new ApiError(resp.ok ? 'INVALID_RESPONSE' : 'UPSTREAM_ERROR', resp.ok ? '服务器返回了非 JSON 数据' : `服务暂不可用（HTTP ${resp.status}）`, resp.status)
    }
  }
  if (body && typeof body === 'object' && 'items' in body && !Array.isArray(body.items)) body.items = []
  if (!resp.ok) {
    const err = body?.error
    throw new ApiError(err?.code || 'UNKNOWN', err?.message || `请求失败 (${resp.status})`, resp.status)
  }
  return (body && typeof body === 'object' ? body : {}) as T
}

export async function get<T>(path: string): Promise<T> {
  return handle<T>(await fetch(path, { credentials: 'same-origin' }))
}

// CSRF 失败自愈：会话有效但本地令牌过期（改密/换会话残留）时，
// 向 /auth/me 取回当前会话的有效令牌并重试一次。
let refreshing: Promise<boolean> | null = null
async function refreshCsrf(): Promise<boolean> {
  if (refreshing) return refreshing
  refreshing = (async () => {
    try {
      const resp = await fetch('/admin/v1/auth/me', { credentials: 'same-origin' })
      if (!resp.ok) return false
      const body = await resp.json()
      if (body?.csrf_token) { setCsrf(body.csrf_token); return true }
      return false
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

async function doRequest<T>(path: string, method: 'POST' | 'PUT' | 'DELETE', body?: unknown): Promise<T> {
  return handle<T>(await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    body: method === 'DELETE' ? undefined : JSON.stringify(body === undefined ? {} : body),
  }))
}

async function mutate<T>(path: string, method: 'POST' | 'PUT' | 'DELETE', body?: unknown): Promise<T> {
  try { return await doRequest<T>(path, method, body) }
  catch (e) {
    if (e instanceof ApiError && e.code === 'CSRF' && (await refreshCsrf())) return doRequest<T>(path, method, body)
    throw e
  }
}

export async function post<T>(path: string, body?: unknown): Promise<T> {
  return mutate<T>(path, 'POST', body)
}

export async function put<T>(path: string, body?: unknown): Promise<T> {
  return mutate<T>(path, 'PUT', body)
}

export async function del<T>(path: string): Promise<T> {
  return mutate<T>(path, 'DELETE')
}

export const qs = (params: Record<string, string | number | undefined>) => {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}
