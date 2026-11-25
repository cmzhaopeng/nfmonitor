import {useEffect, useState} from 'react'
import {HostView, listHosts, Meta, setApiHost, usePoll} from './api'
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

const HOST_KEY = 'nfmonitor.host'
const loadHost = () => { try { return localStorage.getItem(HOST_KEY) || '' } catch { return '' } }
const saveHost = (id: string) => { try { localStorage.setItem(HOST_KEY, id) } catch { /* 无痕模式等 */ } }

export default function App() {
  const [page, setPage] = useState<PageId>('overview')
  const [host, setHostState] = useState(loadHost)
  const [hosts, setHosts] = useState<HostView[]>([])
  const refreshHosts = () => listHosts().then(r => setHosts(r.hosts)).catch(() => {})
  useEffect(() => { refreshHosts() }, [])
  // 记住的主机已被删除：回到本机。
  const known = host === '' || hosts.some(h => h.id === host)
  useEffect(() => { if (hosts.length && !known) choose('') }, [hosts, known])
  const choose = (id: string) => { setHostState(id); saveHost(id) }
  setApiHost(host)
  // 切换主机时整棵树重建：各页的轮询、速率历史、选中状态都从头开始。
  return <Shell key={host} host={host} hosts={hosts} onHost={choose} onHostsChanged={refreshHosts} page={page} setPage={setPage}/>
}

function Shell({host, hosts, onHost, onHostsChanged, page, setPage}: {
  host: string; hosts: HostView[]; onHost: (id: string) => void; onHostsChanged: () => void
  page: PageId; setPage: (p: PageId) => void
}) {
  const meta = usePoll<Meta>('/api/meta', 5000)
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
            <select className="host-pick" value={host} onChange={e => onHost(e.target.value)} aria-label="要监控的主机">
              <option value="">本机</option>
              {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
            </select>
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
                <div><b>连不上 {meta.data.name}</b><div className="dim" style={{overflowWrap: 'anywhere'}}>{meta.data.error}</div></div>
                <span className="sp"/>
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
          {page === 'hosts' && <HostsPage current={host} onUse={id => { onHost(id); setPage('overview') }} onChanged={onHostsChanged}/>}
        </main>
      </div>
    </RatesProvider>
  )
}

export function ErrorBanner({error}: {error: string}) {
  return error ? <div className="banner err">采集失败：{error}</div> : null
}
