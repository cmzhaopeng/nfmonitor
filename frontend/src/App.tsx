import {useEffect, useRef, useState} from 'react'
import {
  canWrite, connectHost, getSession, HostView, isServer, listHosts, logout, Meta, reauth, Session, setApiHost, setLoginHandler,
  setReauthHandler, setSession, usePoll,
} from './api'
import {RatesProvider} from './rates'
import Overview from './pages/Overview'
import Apps from './pages/Apps'
import Interfaces from './pages/Interfaces'
import RoutingPage from './pages/Routing'
import ProxyPage from './pages/Proxy'
import FirewallPage from './pages/Firewall'
import Connections from './pages/Connections'
import HostsPage from './pages/Hosts'
import FleetPage from './pages/Fleet'
import AuditPage from './pages/Audit'
import LoginPage from './pages/Login'
import {Modal} from './pages/Ufw'

const PAGES = [
  {id: 'fleet', label: '所有主机', ico: '▣'},
  {id: 'overview', label: '总览', ico: '◎'},
  {id: 'apps', label: '应用', ico: '▤'},
  {id: 'links', label: '网卡', ico: '⇅'},
  {id: 'routing', label: '路由', ico: '⤳'},
  {id: 'proxy', label: '代理 / TUN', ico: '⇌'},
  {id: 'firewall', label: '防火墙', ico: '▦'},
  {id: 'conns', label: '连接', ico: '≡'},
  {id: 'hosts', label: '主机管理', ico: '⌂'},
  {id: 'audit', label: '审计日志', ico: '✎'},
] as const
export type PageId = typeof PAGES[number]['id']
/** 需要一台「当前主机」的页面。 */
const HOST_PAGES: PageId[] = ['overview', 'apps', 'links', 'routing', 'proxy', 'firewall', 'conns']

/** 先确定运行方式（桌面 / 本机网页 / 服务器版），服务器版没登录时显示登录页。 */
export default function App() {
  const [sess, setSess] = useState<Session | null>(null)
  const [needLogin, setNeedLogin] = useState(false)
  const [bootErr, setBootErr] = useState('')
  const load = () => getSession().then(s => { setSession(s); setSess(s); setNeedLogin(false) })
    .catch(e => { if (!e.login) setBootErr(String(e.message || e)) })
  useEffect(() => {
    setLoginHandler(() => { setSession(null); setSess(null); setNeedLogin(true) })
    load()
    return () => setLoginHandler(null)
  }, [])
  if (needLogin) return <LoginPage onDone={load}/>
  if (!sess) return <div className="page">{bootErr ? <div className="banner err">启动失败：{bootErr}</div> : <div className="empty">加载中…</div>}</div>
  return <Main sess={sess}/>
}

function Main({sess}: {sess: Session}) {
  // 没有「本机」（Windows 客户端、服务器版）时先看所有主机。
  const [page, setPage] = useState<PageId>(sess.local ? 'overview' : 'fleet')
  // 启动时总是看本机（或不选主机）：远程主机只在用户选中（或点「连接」）时才连接。
  const [host, setHost] = useState('')
  const [connecting, setConnecting] = useState('')
  const [hosts, setHosts] = useState<HostView[]>([])
  const refreshHosts = () => listHosts().then(r => setHosts(r.hosts)).catch(() => {})
  useEffect(() => { refreshHosts() }, [])
  // 当前主机已被删除：回到本机（没有本机时回到「所有主机」）。
  const known = host === '' || hosts.some(h => h.id === host)
  useEffect(() => { if (hosts.length && !known) setHost('') }, [hosts, known])
  // 选中远程主机 = 要看它：先连接（包括之前手动断开的），失败时由页面上的横幅显示原因。
  const choose = async (id: string) => {
    if (id) {
      setConnecting(id)
      await connectHost(id).catch(() => {})
      setConnecting('')
    }
    setHost(id)
  }
  setApiHost(host)
  const noTarget = host === '' && !sess.local
  const shown = noTarget && HOST_PAGES.includes(page) ? 'fleet' : page
  // 切换主机时整棵树重建：各页的轮询、速率历史、选中状态都从头开始。
  return <>
    <Shell key={host} sess={sess} host={host} hosts={hosts} connecting={hosts.find(h => h.id === connecting)?.name || ''}
           onHost={choose} onHostsChanged={refreshHosts} page={shown} setPage={setPage}/>
    <Reauth/>
  </>
}

/** 危险操作前的「再次输入口令」（服务器版）：接口返回 reauth 时弹出，确认后原请求自动重发。 */
function Reauth() {
  const [open, setOpen] = useState(false)
  const [pw, setPw] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const done = useRef<((ok: boolean) => void) | null>(null)
  useEffect(() => {
    setReauthHandler(() => new Promise<boolean>(resolve => { done.current = resolve; setPw(''); setErr(''); setOpen(true) }))
    return () => setReauthHandler(null)
  }, [])
  const finish = (ok: boolean) => { setOpen(false); done.current?.(ok); done.current = null }
  const submit = async () => {
    setBusy(true); setErr('')
    try { await reauth(pw); finish(true) } catch (e: any) { setErr(String(e.message || e)) }
    setBusy(false)
  }
  if (!open) return null
  return <Modal title="请再次输入口令" onClose={() => finish(false)} foot={<>
    {err && <div className="form-err" style={{flex: 1}}>{err}</div>}
    <span className="sp"/>
    <button className="btn" onClick={() => finish(false)}>取消</button>
    <button className="btn primary" disabled={busy || !pw} onClick={submit}>{busy ? '验证中…' : '确认'}</button>
  </>}>
    <p style={{marginTop: 0}}>这是会改变主机配置或防火墙的操作。为确认是你本人在操作，请输入登录口令（之后 5 分钟内不再询问）。</p>
    <input type="password" autoFocus autoComplete="current-password" style={{width: '100%'}} value={pw}
           onChange={e => setPw(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && pw) submit() }}/>
  </Modal>
}

function Shell({sess, host, hosts, connecting, onHost, onHostsChanged, page, setPage}: {
  sess: Session; host: string; hosts: HostView[]; connecting: string; onHost: (id: string) => void; onHostsChanged: () => void
  page: PageId; setPage: (p: PageId) => void
}) {
  const noTarget = host === '' && !sess.local
  const meta = usePoll<Meta>(noTarget ? '/api/session' : '/api/meta', 5000)
  const [reconnecting, setReconnecting] = useState(false)
  const reconnect = async () => {
    setReconnecting(true)
    await connectHost(host).catch(() => {})
    setReconnecting(false)
    meta.reload()
  }
  const priv = meta.data?.priv ?? 'none'
  const remote = host !== ''
  const admin = !isServer() || sess.role === 'admin'
  const pages = PAGES.filter(p => (p.id !== 'audit' || (isServer() && admin)) && (!noTarget || !HOST_PAGES.includes(p.id)))
  const signOut = async () => { await logout().catch(() => {}); location.reload() }
  const privLabel = remote
    ? priv === 'root' ? 'root 登录' : priv === 'sudo' ? '经 sudo 取得 root' : '无 root 权限'
    : priv === 'root' ? 'root 运行' : priv === 'none' ? '普通权限' : '已授权读取'
  return (
    <RatesProvider>
      <div className="app">
        <aside className="sidebar">
          <div className="brand">
            <b>nfmonitor</b>
            <select className="host-pick" value={host} disabled={!!connecting} onChange={e => onHost(e.target.value)} aria-label="要监控的主机">
              {sess.local ? <option value="">本机</option> : <option value="">— 选择主机 —</option>}
              {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
            </select>
            {connecting && <div>正在连接 {connecting}…</div>}
            {!noTarget && <div>{meta.data?.hostname || (remote ? '' : '本机')}{remote && meta.data?.kernel && <> · {meta.data.kernel}</>}</div>}
          </div>
          <nav className="nav">
            {pages.map(p => (
              <button key={p.id} className={page === p.id ? 'on' : ''} onClick={() => setPage(p.id)}>
                <span className="ico" aria-hidden="true">{p.ico}</span>{p.label}
              </button>
            ))}
          </nav>
          <div className="side-foot">
            {noTarget ? null : remote && meta.data?.error
              ? <span className="badge crit">未连接</span>
              : <span className={'badge ' + (priv === 'none' ? 'warn' : 'good')}>{privLabel}</span>}
            {isServer() && <div className="who">
              <span title={sess.role === 'admin' ? '管理员' : '只读账号'}>{sess.user} · {sess.role === 'admin' ? '管理员' : '只读'}</span>
              <button className="link" onClick={signOut}>退出</button>
            </div>}
            <span>v{sess.version || '…'}</span>
          </div>
        </aside>
        <main className="main">
          {remote && meta.data?.error && page !== 'hosts' && (
            <div className="page" style={{paddingBottom: 0}}>
              <div className="banner err">
                <div><b>{meta.data.error.startsWith('已断开连接') ? '已断开' : '连不上'} {meta.data.name}</b><div className="dim" style={{overflowWrap: 'anywhere'}}>{meta.data.error}</div></div>
                <span className="sp"/>
                <button className="btn primary" disabled={reconnecting} onClick={reconnect}>{reconnecting ? '连接中…' : '连接'}</button>
                <button className="btn" onClick={() => setPage('hosts')}>检查主机设置</button>
              </div>
            </div>
          )}
          {page === 'fleet' && <FleetPage onOpen={id => { onHost(id === 'local' ? '' : id); setPage('overview') }} onManage={() => setPage('hosts')}/>}
          {page === 'audit' && <AuditPage/>}
          {page === 'overview' && <Overview go={setPage}/>}
          {page === 'apps' && <Apps onPrivChange={meta.reload}/>}
          {page === 'links' && <Interfaces/>}
          {page === 'routing' && <RoutingPage/>}
          {page === 'proxy' && <ProxyPage/>}
          {page === 'firewall' && <FirewallPage onPrivChange={meta.reload} meta={meta.data as Meta | null}/>}
          {page === 'conns' && <Connections/>}
          {page === 'hosts' && <HostsPage current={host} onUse={id => { onHost(id); setPage(id || sess.local ? 'overview' : 'fleet') }} onLeave={() => onHost('')} onChanged={onHostsChanged}/>}
        </main>
      </div>
    </RatesProvider>
  )
}

export function ErrorBanner({error}: {error: string}) {
  return error ? <div className="banner err">采集失败：{error}</div> : null
}
