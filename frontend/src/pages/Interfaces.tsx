import {useState} from 'react'
import {Link, usePoll} from '../api'
import {ErrorBanner} from '../App'
import {CLASS_LABEL, fmtBytes, fmtCount, fmtRate, KIND_LABEL} from '../format'
import {RateChart, Spark} from '../RateChart'
import {lastRate, useRates} from '../rates'

export function StateBadge({l}: {l: Link}) {
  if (l.up) return <span className="badge good">已连接</span>
  if (l.flags.includes('UP')) return <span className="badge warn">无载波</span>
  return <span className="badge">已停用</span>
}

export default function Interfaces() {
  const {data, error} = usePoll<Link[]>('/api/links', 3000)
  const {history} = useRates()
  const [sel, setSel] = useState('')
  const [showDown, setShowDown] = useState(true)
  const links = (data || []).filter(l => showDown || l.up)
  const cur = (data || []).find(l => l.name === sel)

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>网卡</h1><p>物理网卡、隧道（TUN / WireGuard）、网桥等全部接口；点一行看速率曲线</p></div>
        <span className="sp"/>
        <label className="dim"><input type="checkbox" checked={showDown} onChange={e => setShowDown(e.target.checked)}/> 显示未连接的接口</label>
      </div>
      <ErrorBanner error={error}/>
      {cur && (
        <div className="card">
          <div className="card-head">
            <h2>{cur.name}</h2><span className="tag">{KIND_LABEL[cur.kind] || cur.kind}</span><StateBadge l={cur}/>
            <span className="sp"/>
            <div className="legend"><span><i style={{background: 'var(--rx)'}}/>下行</span><span><i style={{background: 'var(--tx)'}}/>上行</span></div>
            <button className="btn" onClick={() => setSel('')}>收起</button>
          </div>
          <RateChart points={history[cur.name] || []}/>
          <div className="dim" style={{marginTop: 8}}>
            MTU {cur.mtu}{cur.mac && <> · MAC <code>{cur.mac}</code></>}{cur.driver && <> · 驱动 {cur.driver}</>}{cur.speed > 0 && <> · 协商速率 {cur.speed} Mb/s</>}
            {cur.master && <> · 从属于 {cur.master}</>} · 收 {fmtCount(cur.stats.rxPackets)} 包 / 发 {fmtCount(cur.stats.txPackets)} 包
            {' '}· 错误 {cur.stats.rxErrors + cur.stats.txErrors} · 丢弃 {cur.stats.rxDropped + cur.stats.txDropped}
          </div>
        </div>
      )}
      <div className="card tbl-wrap">
        <table>
          <thead><tr>
            <th>接口</th><th>类型</th><th>状态</th><th>地址</th>
            <th className="right">下行</th><th className="right">上行</th><th>趋势（下行）</th>
            <th className="right">累计收</th><th className="right">累计发</th><th className="right">丢弃</th>
          </tr></thead>
          <tbody>
          {links.map(l => {
            const h = history[l.name] || [], r = lastRate(h)
            return (
              <tr key={l.name} className={'clickable' + (sel === l.name ? ' sel' : '') + (l.up ? '' : ' off')} onClick={() => setSel(sel === l.name ? '' : l.name)}>
                <td><b>{l.name}</b></td>
                <td><span className="tag">{KIND_LABEL[l.kind] || l.kind}</span> <span className="muted">{CLASS_LABEL[l.class]}</span></td>
                <td><StateBadge l={l}/></td>
                <td>{l.addrs.filter(a => a.scope !== 'link').map(a => <div key={a.local}><code>{a.local}/{a.prefix}</code></div>)}
                  {!l.addrs.some(a => a.scope !== 'link') && <span className="muted">—</span>}</td>
                <td className="right num nowrap">{fmtRate(r.rx)}</td>
                <td className="right num nowrap">{fmtRate(r.tx)}</td>
                <td><Spark values={h.slice(-60).map(p => p.rx)} color="var(--rx)"/></td>
                <td className="right num nowrap">{fmtBytes(l.stats.rxBytes)}</td>
                <td className="right num nowrap">{fmtBytes(l.stats.txBytes)}</td>
                <td className="right num">{l.stats.rxDropped + l.stats.txDropped || <span className="muted">0</span>}</td>
              </tr>
            )
          })}
          </tbody>
        </table>
        {!links.length && <div className="empty">没有接口</div>}
      </div>
    </div>
  )
}
