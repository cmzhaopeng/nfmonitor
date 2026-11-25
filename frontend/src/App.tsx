import {useEffect, useState} from 'react'
import {connectHost, HostView, listHosts, Meta, setApiHost, usePoll} from './api'
import {RatesProvider} from './rates'
import Overview from './pages/Overview'
import Apps from './pages/Apps'
import Interfaces from './pages/Interfaces'
import RoutingPage from './pages/Routing'
import ProxyPage from './pages/Proxy'
import FirewallPage from './pages/Firewall'
import Connections from './pages/Connections'
import HostsPage from './pages/Hosts'

const PAGES = [
  {id: 'overview', label: '总览', ico: '◎'},
  {id: 'apps', label: '应用', ico: '▤'},
  {id: 'links', label: '网卡', ico: '⇅'},
  {id: 'routing', label: '路由', ico: '⤳'},
  {id: 'proxy', label: '代理 / TUN', ico: '⇌'},
  {id: 'firewall', label: '防火墙', ico: '▦'},
  {id: 'conns', label: '连接', ico: '≡'},
  {id: 'hosts', label: '主机管理', ico: '⌂'},
] as const
export type PageId = typeof PAGES[number]['id']

export default function App() {
  const [page, setPage] = useState<PageId>('overview')
  // 启动时总是看本机：远程主机只在用户选中（或点「连接」）时才连接。
  const [host, setHost] = useState('')
  const [connecting, setConnecting] = useState('')
  const [hosts, setHosts] = useState<HostView[]>([])
  const refreshHosts = () => listHosts().then(r => setHosts(r.hosts)).catch(() => {})
  useEffect(() => { refreshHosts() }, [])
  // 当前主机已被删除：回到本机。
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
  // 切换主机时整棵树重建：各页的轮询、速率历史、选中状态都从头开始。
  return <Shell key={host} host={host} hosts={hosts} connecting={hosts.find(h => h.id === connecting)?.name || ''}
                onHost={choose} onHostsChanged={refreshHosts} page={page} setPage={setPage}/>
}

function Shell({host, hosts, connecting, onHost, onHostsChanged, page, setPage}: {
  host: string; hosts: HostView[]; connecting: string; onHost: (id: string) => void; onHostsChanged: () => void
  page: PageId; setPage: (p: PageId) => void
}) {
  const meta = usePoll<Meta>('/api/meta', 5000)
  const [reconnecting, setReconnecting] = useState(false)
  const reconnect = async () => {
    setReconnecting(true)
    await connectHost(host).catch(() => {})
    setReconnecting(false)
    meta.reload()
  }
  const priv = meta.data?.priv ?? 'none'
  const remote = host !== ''
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
              <option value="">本机</option>
              {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
            </select>
            {connecting && <div>正在连接 {connecting}…</div>}
            <div>{meta.data?.hostname || (remote ? '' : '本机')}{remote && meta.data?.kernel && <> · {meta.data.kernel}</>}</div>
          </div>
          <nav className="nav">
            {PAGES.map(p => (
              <button key={p.id} className={page === p.id ? 'on' : ''} onClick={() => setPage(p.id)}>
                <span className="ico" aria-hidden="true">{p.ico}</span>{p.label}
              </button>
            ))}
          </nav>
          <div className="side-foot">
            {remote && meta.data?.error
              ? <span className="badge crit">未连接</span>
              : <span className={'badge ' + (priv === 'none' ? 'warn' : 'good')}>{privLabel}</span>}
            <span>v{meta.data?.version || '…'}</span>
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
          {page === 'overview' && <Overview go={setPage}/>}
          {page === 'apps' && <Apps onPrivChange={meta.reload}/>}
          {page === 'links' && <Interfaces/>}
          {page === 'routing' && <RoutingPage/>}
          {page === 'proxy' && <ProxyPage/>}
          {page === 'firewall' && <FirewallPage onPrivChange={meta.reload} meta={meta.data}/>}
          {page === 'conns' && <Connections/>}
          {page === 'hosts' && <HostsPage current={host} onUse={id => { onHost(id); setPage('overview') }} onLeave={() => onHost('')} onChanged={onHostsChanged}/>}
        </main>
      </div>
    </RatesProvider>
  )
}

export function ErrorBanner({error}: {error: string}) {
  return error ? <div className="banner err">采集失败：{error}</div> : null
}
