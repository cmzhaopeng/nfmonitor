import {useState} from 'react'
import {login} from '../api'

/** 服务器版的登录页。账号在服务器上用 `nfmonitor server user add` 创建。 */
export default function LoginPage({onDone}: {onDone: () => void}) {
  const [user, setUser] = useState('')
  const [pw, setPw] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true); setErr('')
    try { await login(user.trim(), pw); setPw(''); onDone() } catch (x: any) { setErr(String(x.message || x)) }
    setBusy(false)
  }
  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <div className="brand" style={{padding: "0 0 12px"}}><b>nfmonitor</b><div>服务器版</div></div>
        <h1 style={{margin: '0 0 4px', fontSize: 18}}>登录</h1>
        <p className="dim" style={{marginTop: 0}}>集中监控所有纳管主机的网络与安全策略</p>
        <label className="field"><span>用户名</span>
          <input autoFocus autoComplete="username" value={user} onChange={e => setUser(e.target.value)}/></label>
        <label className="field"><span>口令</span>
          <input type="password" autoComplete="current-password" value={pw} onChange={e => setPw(e.target.value)}/></label>
        {err && <div className="form-err">{err}</div>}
        <button className="btn primary" style={{width: '100%', marginTop: 8}} disabled={busy || !user || !pw}>{busy ? '登录中…' : '登录'}</button>
      </form>
    </div>
  )
}
