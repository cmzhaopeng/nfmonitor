import {useState} from 'react'
import {canWrite, FleetHost, FleetReport, usePoll} from '../api'
import {ErrorBanner} from '../App'
import {fmtRate} from '../format'

const STATE: Record<string, [string, string]> = {
  ok: ['good', '在线'], error: ['crit', '连不上'], timeout: ['crit', '超时'], disconnected: ['plain', '已断开'],
}
const LEVEL_ORDER: Record<string, number> = {crit: 0, warn: 1, info: 2}

function fwText(h: FleetHost): [string, string] {
  const f = h.fw
  if (!f) return ['plain', '—']
  if (f.ufw === 'active') return [f.ufwIncoming === 'allow' ? 'warn' : 'good', `ufw 已启用 · 入站默认 ${f.ufwIncoming || '?'} · ${f.ufwRules} 条规则`]
  if (f.firewalld === 'running') return ['good', `firewalld 运行中 · 默认区域 ${f.firewalldZone || '?'}`]
  if (!f.privileged) return ['warn', '没有 root，读不到完整规则']
  if (f.inputFiltering) return ['good', `${f.backend || 'nftables'} · ${f.rules} 条规则 · 入站有过滤`]
  return ['crit', '没有启用防火墙']
}

function worst(h: FleetHost) {
  if (h.state !== 'ok') return h.state === 'disconnected' ? 3 : 0
  return Math.min(3, ...h.findings.map(f => LEVEL_ORDER[f.level] ?? 3))
}

/** 「所有主机」：每台主机的连接状态、流量、对外端口、防火墙，以及需要注意的问题。 */
export default function FleetPage({onOpen, onManage}: {onOpen: (id: string) => void; onManage: () => void}) {
  const {data, error, loading} = usePoll<FleetReport>('/api/fleet', 20000)
  const [open, setOpen] = useState<string>('')
  const hosts = [...(data?.hosts || [])].sort((a, b) => worst(a) - worst(b) || a.name.localeCompare(b.name))
  const live = hosts.filter(h => h.state === 'ok')
  const down = hosts.filter(h => h.state === 'error' || h.state === 'timeout')
  const crit = hosts.reduce((n, h) => n + h.findings.filter(f => f.level === 'crit').length, 0)
  const warn = hosts.reduce((n, h) => n + h.findings.filter(f => f.level === 'warn').length, 0)
  const exposed = live.reduce((n, h) => n + (h.net?.exposed.length || 0), 0)
  return (
    <div className="page">
      <div className="page-head">
        <div><h1>所有主机</h1><p>所有纳管主机的网络与安全策略概况，每 20 秒刷新（同一份结果最多缓存 15 秒）</p></div>
        <span className="sp"/>
        <button className="btn" onClick={onManage}>{canWrite() ? '管理主机' : '主机列表'}</button>
      </div>
      <ErrorBanner error={error}/>
      <div className="grid tiles">
        <div className="card tile"><div className="label">主机</div><div className="value num">{live.length} / {hosts.length}</div>
          <div className="sub">{down.length ? `${down.length} 台连不上` : '在线 / 全部'}</div></div>
        <div className="card tile"><div className="label">严重问题</div><div className="value num" style={{color: crit ? 'var(--crit)' : undefined}}>{crit}</div>
          <div className="sub">另有 {warn} 条需要注意</div></div>
        <div className="card tile"><div className="label">对外监听端口</div><div className="value num">{exposed}</div>
          <div className="sub">监听在非回环地址上</div></div>
        <div className="card tile"><div className="label">已建立连接</div><div className="value num">{live.reduce((n, h) => n + (h.net?.estab || 0), 0)}</div>
          <div className="sub">所有在线主机合计</div></div>
      </div>
      <div className="card">
        {hosts.length ? <div className="tbl-wrap"><table>
          <thead><tr><th>主机</th><th>状态</th><th>流量</th><th>连接 / 监听</th><th>防火墙</th><th>问题</th><th/></tr></thead>
          <tbody>{hosts.map(h => {
            const [scls, slabel] = STATE[h.state] || ['plain', h.state]
            const [fcls, ftext] = fwText(h)
            const finds = [...h.findings].sort((a, b) => (LEVEL_ORDER[a.level] ?? 3) - (LEVEL_ORDER[b.level] ?? 3))
            const expanded = open === h.id
            return [
              <tr key={h.id} className={'clickable' + (expanded ? ' sel' : '')} onClick={() => setOpen(expanded ? '' : h.id)}>
                <td><b>{h.name}</b><div className="dim mono" style={{fontSize: 12}}>{h.addr || h.hostname}</div></td>
                <td><span className={'badge ' + scls} title={h.error || ''}>{slabel}</span>
                  {h.state === 'ok' && h.priv === 'none' && <div><span className="badge warn">无 root</span></div>}</td>
                <td className="num nowrap">{h.net && h.net.rxRate >= 0 ? <>↓ {fmtRate(h.net.rxRate)}<br/>↑ {fmtRate(h.net.txRate)}</> : '—'}</td>
                <td className="num">{h.net ? <>{h.net.estab} / {h.net.listens}{h.net.exposed.length > 0 && <div className="dim">{h.net.exposed.length} 个对外</div>}</> : '—'}</td>
                <td><span className={'badge ' + fcls}>{ftext}</span></td>
                <td>{h.state !== 'ok'
                  ? <span className="form-err" style={{overflowWrap: 'anywhere'}}>{h.error || slabel}</span>
                  : finds.length ? finds.slice(0, 2).map((f, i) => <div key={i}><span className={'badge ' + f.level}>{f.text}</span></div>)
                    : <span className="badge good">没有发现问题</span>}
                  {finds.length > 2 && <div className="dim">还有 {finds.length - 2} 条</div>}</td>
                <td className="right nowrap">{h.state === 'ok' && <button className="btn" onClick={e => { e.stopPropagation(); onOpen(h.id) }}>详情</button>}</td>
              </tr>,
              expanded && <tr key={h.id + '-x'} className="sel"><td colSpan={7}><HostDetail h={h}/></td></tr>,
            ]
          })}</tbody>
        </table></div> : <div className="empty">{loading ? '正在采集各主机…' : canWrite()
          ? <>还没有纳管主机。<button className="link" onClick={onManage}>去添加</button></>
          : '还没有纳管主机，请联系管理员添加。'}</div>}
      </div>
    </div>
  )
}

function HostDetail({h}: {h: FleetHost}) {
  const n = h.net
  return <div className="grid two" style={{gap: 16}}>
    <div>
      <b>网络</b>
      <div className="dim" style={{margin: '4px 0'}}>{h.hostname}{h.kernel && ' · ' + h.kernel} · 网卡 {n?.upIfaces ?? '—'} / {n?.ifaces ?? '—'} 已启用</div>
      {n?.addrs.length ? <div className="mono" style={{fontSize: 12, overflowWrap: 'anywhere'}}>{n.addrs.join('  ')}</div> : null}
      <div style={{marginTop: 8}}><b>对外监听端口</b></div>
      {n?.exposed.length ? <table style={{marginTop: 4}}><tbody>{n.exposed.slice(0, 30).map((p, i) =>
        <tr key={i}><td className="mono">{p.proto}</td><td className="mono">{p.addr}:{p.port}</td><td>{p.process || <span className="dim">（无 root 看不到进程）</span>}</td></tr>)}
      </tbody></table> : <div className="dim">无</div>}
      {n && n.topPeers.length > 0 && <>
        <div style={{marginTop: 8}}><b>连接最多的对端</b></div>
        <div className="mono" style={{fontSize: 12}}>{n.topPeers.map(p => `${p.peer} ×${p.conns}`).join('  ')}</div>
      </>}
    </div>
    <div>
      <b>安全策略</b>
      {h.fw ? <ul style={{margin: '4px 0', paddingLeft: 18}}>
        <li>ufw：{h.fw.ufw === '' ? '未安装' : h.fw.ufw === 'active' ? `已启用，入站默认 ${h.fw.ufwIncoming}，${h.fw.ufwRules} 条规则` : '未启用'}</li>
        <li>firewalld：{h.fw.firewalld === '' ? '未安装' : h.fw.firewalld === 'running' ? `运行中，默认区域 ${h.fw.firewalldZone}` : '未运行'}</li>
        <li>内核规则：{h.fw.privileged ? `${h.fw.backend || '—'}，${h.fw.tables} 个表，${h.fw.rules} 条规则，入站默认策略 ${h.fw.inputPolicy || '—'}` : '需要 root 才能读取'}</li>
      </ul> : <div className="dim">—</div>}
      <div style={{marginTop: 8}}><b>需要注意</b></div>
      {h.findings.length ? <ul style={{margin: '4px 0', paddingLeft: 18}}>{h.findings.map((f, i) =>
        <li key={i}><span className={'badge ' + f.level}>{f.level === 'crit' ? '严重' : f.level === 'warn' ? '注意' : '提示'}</span> {f.text}</li>)}</ul>
        : <div className="dim">没有发现问题</div>}
      <div className="dim" style={{fontSize: 12}}>采集用时 {h.tookMs} ms · {new Date(h.time).toLocaleTimeString()}</div>
    </div>
  </div>
}
