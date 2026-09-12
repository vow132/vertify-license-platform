import { useEffect, useState } from 'react'
import { get } from '../api'

interface KeysData {
  kex_keys: { kid: string; pub: string; alg: string; active: boolean; created_at: string }[]
  sign_kids: string[]
  active: string
}

export default function Keys() {
  const [data, setData] = useState<KeysData | null>(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    get<KeysData>('/admin/v1/keys').then(setData).catch((e) => setErr(e.message))
  }, [])
  if (err) return <div className="panel error-text">{err}</div>
  if (!data) return <div className="panel muted">加载中…</div>
  return (
    <>
      <h2 className="page-title">密钥状态（只读）</h2>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>信封加密密钥（X25519）</h3>
        <div className="table-wrap"><table>
          <thead><tr><th>KID</th><th>算法</th><th>状态</th><th>创建时间</th><th>公钥（base64url）</th></tr></thead>
          <tbody>
            {data.kex_keys.map((k) => (
              <tr key={k.kid}>
                <td className="mono">{k.kid}</td>
                <td className="mono">{k.alg}</td>
                <td>{k.active ? <span className="badge ok">使用中</span> : <span className="badge">已停用</span>}</td>
                <td className="muted">{new Date(k.created_at).toLocaleString()}</td>
                <td className="mono" style={{ wordBreak: 'break-all' }}>{k.pub}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
        <p className="muted">私钥仅存于 KMS/Secret，此处只展示公钥指纹。</p>
      </div>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>签名密钥（Ed25519）</h3>
        <div className="kv">
          <div className="k">当前签名 KID</div><div className="mono">{data.active}</div>
          <div className="k">全部可信 KID</div><div className="mono">{data.sign_kids.join(', ')}</div>
        </div>
        <p className="muted">轮换流程：生成新 KID 并入配置 → 新旧并存观察客户端兼容率 → 移除旧 KID。</p>
      </div>
    </>
  )
}
