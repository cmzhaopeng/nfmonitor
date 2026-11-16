import {useEffect, useState} from 'react'
import {Firewall, Link, ProxyInfo, RouteGet, Routing, Socket, usePoll} from '../api'
import {ErrorBanner, PageId} from '../App'
import {fmtRate, KIND_LABEL} from '../format'
import {RateChart} from '../RateChart'
import {lastRate, useRates} from '../rates'

const PROBE = '1.1.1.1' // 只用来问内核"公网流量走哪"，不会真的发包

export default function Overview({go}: {go: (p: PageId) => void}) {
  const links = usePoll<Link[]>('/api/links', 5000)
  const routing = usePoll<Routing>('/api/routing', 10000)
  const proxy = usePoll<ProxyInfo>('/api/proxy', 10000)
  const fw = usePoll<Firewall>('/api/firewall', 15000)
  const socks = usePoll<Socket[]>('/api/sockets', 5000)
  const probe = usePoll<RouteGet>('/api/routeget?dst=' + PROBE, 10000)
  const {history, error: rateErr} = useRates()

  const all = links.data || []
  const main = routing.data?.tables.find(t => t.id === 'main')
  const defRoute = main?.routes.find(r => r.dst === 'default' && r.family === 'inet')
  const physDev = defRoute?.dev || all.find(l => l.class === 'physical' && l.up)?.name || ''
  const [iface, setIface] = useState('')
  useEffect(() => { if (!iface && physDev) setIface(physDev) }, [physDev, iface])

  const out = probe.data
  const outLink = all.find(l => l.name === out?.dev)
  const viaTunnel = outLink?.class === 'tunnel'
  const tunnelProc = viaTunnel ? proxy.data?.processes.find(p => out!.dev.toLowerCase().includes(p.name.toLowerCase().replace(/[^a-z]/g, '').slice(0, 4))) : undefined
  const envProxy = proxy.data?.settings.find(s => s.listen || s.host)
  const r = lastRate(history[iface])
  const conns = (socks.data || []).filter(s => s.state === 'ESTAB').length
  const listens = (socks.data || []).filter(s => s.state === 'LISTEN').length
  const baseChains = (fw.data?.tables || []).flatMap(t => t.chains).filter(c => c.base)
  const dropPolicies = baseChains.filter(c => c.policy === 'drop').length

  return (
    <div className="page">
      <div className="page-head"><div><h1>总览</h1><p>本机流量、出口路径与防护状态</p></div></div>
      <ErrorBanner error={links.error || rateErr}/>

      <div className="grid tiles">
        <div className="card tile">
          <div className="label">下行 · {iface || '—'}</div>
          <div className="value num">{fmtRate(r.rx)}</div>
          <div className="sub num">上行 {fmtRate(r.tx)}</div>
        </div>
        <div className="card tile">
          <div className="label">公网出口</div>
          <div className="value">{out?.dev || '—'}</div>
          <div className="sub">{out ? <>路由表 {out.table}{viaTunnel ? ' · 经隧道' : ' · 直连'}</> : probe.error || '查询中…'}</div>
        </div>
        <div className="card tile">
          <div className="label">应用层代理</div>
          <div className="value">{envProxy ? `${envProxy.host}:${envProxy.port}` : '未设置'}</div>
          <div className="sub">{envProxy ? (envProxy.process ? `由 ${envProxy.process} 提供` : envProxy.listen ? '本机在监听' : '未确认监听') : '环境变量 / 系统代理均为空'}</div>
        </div>
        <div className="card tile">
          <div className="label">防火墙</div>
          {fw.data?.privileged ? <>
            <div className="value">{baseChains.length} 条基链</div>
            <div className="sub">ufw {fw.data.ufwStatus === 'active' ? '已启用' : fw.data.ufwStatus === 'inactive' ? '未启用' : '未安装'} · {dropPolicies} 条默认丢弃</div>
          </> : <>
            <div className="value">需要授权</div>
            <div className="sub"><button className="link" style={{fontFamily: 'inherit'}} onClick={() => go('firewall')}>去防火墙页授权读取 →</button></div>
          </>}
        </div>
        <div className="card tile">
          <div className="label">连接</div>
          <div className="value num">{conns}</div>
          <div className="sub">已建立 TCP · {listens} 个监听端口</div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h2>实时速率</h2>
          <select value={iface} onChange={e => setIface(e.target.value)}>
            {all.filter(l => l.kind !== 'loopback').map(l => <option key={l.name} value={l.name}>{l.name} · {KIND_LABEL[l.kind] || l.kind}{l.up ? '' : '（未连接）'}</option>)}
          </select>
          <span className="sp"/>
          <div className="legend"><span><i style={{background: 'var(--rx)'}}/>下行</span><span><i style={{background: 'var(--tx)'}}/>上行</span></div>
        </div>
        <RateChart points={history[iface] || []}/>
      </div>

      <div className="card">
        <div className="card-head"><h2>公网流量路径</h2><span className="muted">以 {PROBE} 为例，按当前路由状态推出</span></div>
        {out ? (
          <div className="flow">
            <div className="node"><span className="k">起点</span><span className="v">本机应用</span></div>
            {envProxy && <>
              <span className="arrow">→</span>
              <div className="node"><span className="k">应用层代理（仅认代理设置的程序）</span><span className="v">{envProxy.host}:{envProxy.port}</span>
                <span className="s">{envProxy.process || '进程未知'}</span></div>
            </>}
            <span className="arrow">→</span>
            <div className="node hl"><span className="k">策略路由</span><span className="v">表 {out.table}</span>
              <span className="s">{routing.data ? `${routing.data.rules.filter(x => x.family === 'inet').length} 条规则` : ''}</span></div>
            <span className="arrow">→</span>
            <div className="node"><span className="k">{viaTunnel ? '隧道设备' : '出口网卡'}</span><span className="v">{out.dev}</span>
              <span className="s">{KIND_LABEL[outLink?.kind || ''] || outLink?.kind} · 下一跳 {out.gateway || '直连'}</span></div>
            {viaTunnel && <>
              <span className="arrow">→</span>
              <div className="node"><span className="k">隧道程序</span><span className="v">{tunnelProc?.name || '未识别'}</span>
                <span className="s">{tunnelProc ? `pid ${tunnelProc.pid} · 加密 / 分流后重新发出` : '读取 TUN 的进程'}</span></div>
              <span className="arrow">→</span>
              <div className="node"><span className="k">物理出口</span><span className="v">{defRoute?.dev || '—'}</span>
                <span className="s">网关 {defRoute?.gateway || '—'}</span></div>
            </>}
            <span className="arrow">→</span>
            <div className="node"><span className="k">终点</span><span className="v">互联网</span></div>
          </div>
        ) : <div className="empty">{probe.error || '查询中…'}</div>}
        <div className="muted" style={{marginTop: 8}}>
          想查具体地址：<button className="link" style={{fontFamily: 'inherit'}} onClick={() => go('routing')}>路由页的出口测试</button>
          ；想看隧道由哪些规则接管：<button className="link" style={{fontFamily: 'inherit'}} onClick={() => go('proxy')}>代理 / TUN</button>
        </div>
      </div>
    </div>
  )
}
