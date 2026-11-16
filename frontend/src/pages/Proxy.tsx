import {ProxyInfo, usePoll} from '../api'
import {ErrorBanner} from '../App'
import {KIND_LABEL} from '../format'
import {RuleRow} from './Routing'

const SRC_LABEL: Record<string, string> = {env: '环境变量', gnome: 'GNOME 系统代理', '/etc/environment': '/etc/environment'}
const MODE_LABEL: Record<string, string> = {none: '未启用', manual: '手动', auto: '自动（PAC）'}

export default function ProxyPage() {
  const {data, error} = usePoll<ProxyInfo>('/api/proxy', 5000)
  return (
    <div className="page">
      <div className="page-head">
        <div><h1>代理 / TUN</h1><p>应用层代理（环境变量、系统代理）与网络层接管（TUN + 策略路由）是两条独立的路，这里分开列出</p></div>
      </div>
      <ErrorBanner error={error}/>
      {data && <div className="stack">
        <div className="card">
          <div className="card-head">
            <h2>代理设置</h2>
            {data.gnomeMode && <span className="tag">GNOME 系统代理：{MODE_LABEL[data.gnomeMode] || data.gnomeMode}</span>}
            <span className="muted">环境变量取自本程序的启动环境，其他终端里的值可能不同</span>
          </div>
          {data.settings.length ? (
            <div className="tbl-wrap"><table>
              <thead><tr><th>来源</th><th>项</th><th>值</th><th>本机监听</th><th>进程</th></tr></thead>
              <tbody>
              {data.settings.map((s, i) => (
                <tr key={i}>
                  <td>{SRC_LABEL[s.source] || s.source}</td>
                  <td><code>{s.key}</code></td>
                  <td><code>{s.value}</code></td>
                  <td>{!s.port ? <span className="muted">—</span> : s.listen ? <span className="badge good">在监听</span>
                    : /^(127\.|localhost$|::1$)/.test(s.host) ? <span className="badge crit">端口无人监听</span> : <span className="muted">远程地址</span>}</td>
                  <td>{s.process ? <>{s.process} <span className="muted">pid {s.pid}</span></> : <span className="muted">{s.listen ? '未知（需授权）' : '—'}</span>}</td>
                </tr>
              ))}
              </tbody>
            </table></div>
          ) : <div className="empty">没有发现代理设置</div>}
          {data.noProxy && <div className="dim" style={{marginTop: 10}}>不走代理（no_proxy）：<code style={{overflowWrap: 'anywhere'}}>{data.noProxy}</code></div>}
        </div>

        <div className="card">
          <div className="card-head"><h2>隧道设备</h2><span className="muted">哪些策略规则把流量导进了隧道</span></div>
          {data.tunnels.length ? data.tunnels.map(t => (
            <div key={t.name} style={{padding: '10px 0', borderTop: '1px solid var(--border)'}}>
              <div className="card-head" style={{marginBottom: 6}}>
                <b>{t.name}</b><span className="tag">{KIND_LABEL[t.kind] || t.kind}</span>
                <span className={'badge ' + (t.up ? 'good' : '')}>{t.up ? '已连接' : '未连接'}</span>
                {t.default && <span className="badge info">接管默认出口</span>}
                <span className="dim">{t.addrs.join('  ')} · MTU {t.mtu}</span>
              </div>
              <div className="dim" style={{marginBottom: 6}}>
                {t.tables.length ? <>路由表 {t.tables.map(x => <span className="tag" key={x} style={{marginRight: 4}}>{x}</span>)} 中共有 {t.routeCount} 条路由经由此设备</>
                  : '没有路由经由此设备'}
              </div>
              {t.rules.length > 0 && <div className="rule-list">{t.rules.map((r, i) => <RuleRow key={i} r={r}/>)}</div>}
            </div>
          )) : <div className="empty">没有隧道设备</div>}
        </div>

        <div className="card">
          <div className="card-head"><h2>代理 / VPN 进程</h2><span className="muted">按已知程序名识别</span></div>
          {data.processes.length ? (
            <div className="tbl-wrap"><table>
              <thead><tr><th>进程</th><th>类型</th><th>PID</th><th>用户</th><th>监听</th><th>命令行</th></tr></thead>
              <tbody>
              {data.processes.map(p => (
                <tr key={p.pid}>
                  <td><b>{p.name}</b></td>
                  <td><span className="tag">{p.kind === 'vpn' ? 'VPN' : '代理'}</span></td>
                  <td className="num">{p.pid}</td>
                  <td>{p.user}</td>
                  <td>{p.listens.length ? p.listens.map(l => <div key={l}><code>{l}</code></div>) : <span className="muted">—</span>}</td>
                  <td><code className="dim" style={{overflowWrap: 'anywhere'}}>{p.cmdline.length > 160 ? p.cmdline.slice(0, 160) + '…' : p.cmdline}</code></td>
                </tr>
              ))}
              </tbody>
            </table></div>
          ) : <div className="empty">没有发现已知的代理 / VPN 进程</div>}
        </div>
      </div>}
    </div>
  )
}
