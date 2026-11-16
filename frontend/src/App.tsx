import {useState} from 'react'
import {Meta, usePoll} from './api'
import {RatesProvider} from './rates'
import Overview from './pages/Overview'
import Apps from './pages/Apps'
import Interfaces from './pages/Interfaces'
import RoutingPage from './pages/Routing'
import ProxyPage from './pages/Proxy'
import FirewallPage from './pages/Firewall'
import Connections from './pages/Connections'

const PAGES = [
  {id: 'overview', label: '总览', ico: '◎'},
  {id: 'apps', label: '应用', ico: '▤'},
  {id: 'links', label: '网卡', ico: '⇅'},
  {id: 'routing', label: '路由', ico: '⤳'},
  {id: 'proxy', label: '代理 / TUN', ico: '⇌'},
  {id: 'firewall', label: '防火墙', ico: '▦'},
  {id: 'conns', label: '连接', ico: '≡'},
] as const
export type PageId = typeof PAGES[number]['id']

export default function App() {
  const [page, setPage] = useState<PageId>('overview')
  const meta = usePoll<Meta>('/api/meta', 5000)
  const priv = meta.data?.priv ?? 'none'
  return (
    <RatesProvider>
      <div className="app">
        <aside className="sidebar">
          <div className="brand"><b>nfmonitor</b><div>{meta.data?.hostname || '本机'}</div></div>
          <nav className="nav">
            {PAGES.map(p => (
              <button key={p.id} className={page === p.id ? 'on' : ''} onClick={() => setPage(p.id)}>
                <span className="ico" aria-hidden="true">{p.ico}</span>{p.label}
              </button>
            ))}
          </nav>
          <div className="side-foot">
            <span className={'badge ' + (priv === 'none' ? 'warn' : 'good')}>
              {priv === 'none' ? '普通权限' : priv === 'root' ? 'root 运行' : '已授权读取'}
            </span>
            <span>v{meta.data?.version || '…'} · 只读</span>
          </div>
        </aside>
        <main className="main">
          {page === 'overview' && <Overview go={setPage}/>}
          {page === 'apps' && <Apps onPrivChange={meta.reload}/>}
          {page === 'links' && <Interfaces/>}
          {page === 'routing' && <RoutingPage/>}
          {page === 'proxy' && <ProxyPage/>}
          {page === 'firewall' && <FirewallPage onPrivChange={meta.reload}/>}
          {page === 'conns' && <Connections/>}
        </main>
      </div>
    </RatesProvider>
  )
}

export function ErrorBanner({error}: {error: string}) {
  return error ? <div className="banner err">采集失败：{error}</div> : null
}
