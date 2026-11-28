import {Fragment, useEffect, useMemo, useRef, useState} from 'react'
import {App, AppIface, AppsSnapshot, elevate, isRemote, Socket, usePoll} from '../api'
import {ErrorBanner} from '../App'
import {fmtBytes, fmtRate} from '../format'
import {Spark} from '../RateChart'

type View = 'app' | 'dev'
const total = (x: {rxTotal: number; txTotal: number}) => x.rxTotal + x.txTotal
const rate = (x: {rxRate: number; txRate: number}) => x.rxRate + x.txRate
const appLabel = (n: string) => n || '未知（其他用户的进程）'
const ifKey = (i: AppIface) => i.dev + '|' + i.via

// 表头排序：null = 自动（按当前速率）；点表头依次切换 降序 → 升序 → 自动（名称列先升序）。
type SortKey = 'name' | 'conns' | 'rx' | 'tx' | 'rxTotal' | 'txTotal'
type Sort = {key: SortKey; desc: boolean} | null
type Row = {conns: number; rxRate: number; txRate: number; rxTotal: number; txTotal: number}
const sortVal: Record<Exclude<SortKey, 'name'>, (x: Row) => number> = {
  conns: x => x.conns, rx: x => x.rxRate, tx: x => x.txRate, rxTotal: x => x.rxTotal, txTotal: x => x.txTotal,
}
/** 按用户选的列比较；数值相同时按名称，保证顺序稳定。 */
function cmpBy(s: Exclude<Sort, null>, a: Row, an: string, b: Row, bn: string) {
  const byName = appLabel(an).localeCompare(appLabel(bn))
  if (s.key === 'name') return s.desc ? -byName : byName
  const d = sortVal[s.key](a) - sortVal[s.key](b)
  return (s.desc ? -d : d) || byName
}
function nextSort(cur: Sort, key: SortKey): Sort {
  const first = key !== 'name'
  if (!cur || cur.key !== key) return {key, desc: first}
  return cur.desc === first ? {key, desc: !first} : null
}

function SortTh({k, sort, setSort, right, children}: {k: SortKey; sort: Sort; setSort: (s: Sort) => void; right?: boolean; children: React.ReactNode}) {
  const on = sort?.key === k
  return (
    <th className={'sortable' + (right ? ' right' : '') + (on ? ' on' : '')} aria-sort={on ? (sort!.desc ? 'descending' : 'ascending') : 'none'}
      title="点击排序：降序 → 升序 → 自动" onClick={() => setSort(nextSort(sort, k))}>
      {children}<span className="sort-ind">{on ? (sort!.desc ? '▼' : '▲') : ''}</span>
    </th>
  )
}

/** 网卡标签：回环连到本机另一个程序时写成「lo → gost」。 */
export function IfaceTag({i}: {i: {dev: string; via: string}}) {
  return <span className="tag" title={i.via ? `回环连接，对端是本机的 ${i.via}` : undefined}>{i.dev || '未知网卡'}{i.via && <> → {i.via}</>}</span>
}

function AppDetail({app, socks, udpOn}: {app: App; socks: Socket[]; udpOn: boolean}) {
  const conns = socks.filter(s => s.app === app.name && s.proto === 'tcp' && s.state !== 'LISTEN')
    .sort((a, b) => (b.bytesSent + b.bytesRecv) - (a.bytesSent + a.bytesRecv))
  const listens = socks.filter(s => s.app === app.name && (s.state === 'LISTEN' || s.proto === 'udp'))
  return (
    <div className="app-detail">
      <div>
        <h3>各网卡流量</h3>
        {app.ifaces.length ? <table><thead><tr>
          <th>网卡</th><th className="right">连接</th><th className="right">下行</th><th className="right">上行</th><th className="right">累计收</th><th className="right">累计发</th>
          {udpOn && <th className="right" title="累计值里 UDP 占的部分（收 / 发）">其中 UDP</th>}
        </tr></thead><tbody>{app.ifaces.map(i => (
          <tr key={ifKey(i)} className={i.conns || rate(i) > 0 ? '' : 'off'}>
            <td><IfaceTag i={i}/></td><td className="right num">{i.conns}</td>
            <td className="right num nowrap">{fmtRate(i.rxRate)}</td><td className="right num nowrap">{fmtRate(i.txRate)}</td>
            <td className="right num nowrap">{fmtBytes(i.rxTotal)}</td><td className="right num nowrap">{fmtBytes(i.txTotal)}</td>
            {udpOn && <td className="right num nowrap dim">{i.udpRx + i.udpTx > 0 ? `${fmtBytes(i.udpRx)} / ${fmtBytes(i.udpTx)}` : '—'}</td>}
          </tr>))}</tbody></table> : <div className="muted">{udpOn ? '没有流量' : '没有 TCP 连接'}</div>}
        {listens.length > 0 && <>
          <h3 style={{marginTop: 12}}>监听 / UDP</h3>
          <div className="dim">{listens.slice(0, 24).map((s, i) => <code key={i} style={{marginRight: 10, whiteSpace: 'nowrap'}}>{s.proto} {s.local}:{s.localPort}</code>)}
            {listens.length > 24 && <span className="muted">等 {listens.length} 个</span>}</div>
        </>}
        {app.procs.length > 0 && <>
          <h3 style={{marginTop: 12}}>进程（{app.procs.length}）</h3>
          {app.procs.slice(0, 8).map(p => (
            <div key={p.pid} className="dim" style={{overflowWrap: 'anywhere'}}>
              <span className="num">{p.pid}</span> <span className="muted">{p.user} · {p.conns} 连接</span> <code>{p.cmdline.length > 140 ? p.cmdline.slice(0, 140) + '…' : p.cmdline}</code>
            </div>))}
          {app.procs.length > 8 && <div className="muted">等 {app.procs.length} 个进程</div>}
        </>}
      </div>
      <div>
        <h3>当前 TCP 连接（{conns.length}）</h3>
        {conns.length ? <table><thead><tr><th>网卡</th><th>本地</th><th>远端</th><th className="right">已收</th><th className="right">已发</th></tr></thead>
          <tbody>{conns.slice(0, 15).map((s, i) => (
            <tr key={i}>
              <td><span className="tag">{s.dev || '未知'}</span></td>
              <td><code>{s.local}:{s.localPort}</code></td><td><code>{s.peer}:{s.peerPort}</code></td>
              <td className="right num nowrap">{fmtBytes(s.bytesRecv)}</td><td className="right num nowrap">{fmtBytes(s.bytesSent)}</td>
            </tr>))}</tbody></table> : <div className="muted">没有连接</div>}
        {conns.length > 15 && <div className="muted" style={{marginTop: 4}}>仅显示流量最大的 15 条</div>}
      </div>
    </div>
  )
}

export default function Apps({onPrivChange}: {onPrivChange: () => void}) {
  const {data, error, reload} = usePoll<AppsSnapshot>('/api/apps', 2000)
  const [busy, setBusy] = useState(false)
  const [authErr, setAuthErr] = useState('')
  const auth = async () => {
    setBusy(true); setAuthErr('')
    try { await elevate(); onPrivChange(); reload() } catch (e: any) { setAuthErr(String(e.message || e)) }
    setBusy(false)
  }
  const udpOn = data?.udpMode === 'on'
  const [view, setView] = useState<View>('app')
  const [q, setQ] = useState('')
  const [onlyActive, setOnlyActive] = useState(false)
  const [open, setOpen] = useState<string | null>(null)
  const [sort, setSort] = useState<Sort>(null)
  const socks = usePoll<Socket[]>(open != null ? '/api/sockets' : '/api/meta', open != null ? 3000 : 0)
  const hist = useRef<Map<string, number[]>>(new Map())
  const lastT = useRef(0)

  // 每个新采样往各应用的趋势线里追加一个点（下行 + 上行）。
  useEffect(() => {
    if (!data || data.time === lastT.current) return
    lastT.current = data.time
    const m = new Map<string, number[]>()
    for (const a of data.apps) m.set(a.name, [...(hist.current.get(a.name) || []).slice(-39), rate(a)])
    hist.current = m
  }, [data])

  const apps = useMemo(() => (data?.apps || [])
    .filter(a => !q || `${appLabel(a.name)} ${a.ifaces.map(i => i.dev + ' ' + i.via).join(' ')} ${a.procs.map(p => p.pid).join(' ')}`.toLowerCase().includes(q.toLowerCase()))
    .filter(a => !onlyActive || total(a) > 0 || rate(a) > 0)
    .sort((a, b) => sort ? cmpBy(sort, a, a.name, b, b.name)
      : rate(b) - rate(a) || total(b) - total(a) || b.conns - a.conns || a.name.localeCompare(b.name)), [data, q, onlyActive, sort])

  const devs = useMemo(() => {
    const m = new Map<string, {dev: string; rxRate: number; txRate: number; rxTotal: number; txTotal: number; conns: number; apps: {app: App; i: AppIface}[]}>()
    for (const a of apps) for (const i of a.ifaces) {
      const k = i.dev || ''
      let d = m.get(k)
      if (!d) m.set(k, d = {dev: k, rxRate: 0, txRate: 0, rxTotal: 0, txTotal: 0, conns: 0, apps: []})
      d.rxRate += i.rxRate; d.txRate += i.txRate; d.rxTotal += i.rxTotal; d.txTotal += i.txTotal; d.conns += i.conns
      d.apps.push({app: a, i})
    }
    for (const d of m.values()) d.apps.sort((x, y) => sort ? cmpBy(sort, x.i, x.app.name, y.i, y.app.name)
      : rate(y.i) - rate(x.i) || total(y.i) - total(x.i) || y.i.conns - x.i.conns)
    return [...m.values()].sort((a, b) => total(b) - total(a) || b.conns - a.conns)
  }, [apps, sort])
  const th = (k: SortKey, label: string, right = true) => <SortTh k={k} sort={sort} setSort={setSort} right={right}>{label}</SortTh>
  const unknown = (data?.apps || []).some(a => !a.name)

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>应用</h1><p>每个应用走哪块网卡、有多少流量。{udpOn ? '统计 TCP 和 UDP（含 QUIC）的载荷字节' : '目前只统计了 TCP'}，累计值从 {data ? new Date(data.since).toLocaleTimeString() : '…'} 开始监测起算</p></div>
        <span className="sp"/>
        {sort && <button className="link" style={{fontFamily: "inherit"}} onClick={() => setSort(null)} title="恢复按当前速率自动排序">恢复自动排序</button>}
        <label className="dim"><input type="checkbox" checked={onlyActive} onChange={e => setOnlyActive(e.target.checked)}/> 只看有流量的</label>
        <input type="search" placeholder="按应用 / 网卡 / PID 过滤" value={q} onChange={e => setQ(e.target.value)} style={{width: 200}}/>
        <div className="seg">
          <button className={view === 'app' ? 'on' : ''} onClick={() => setView('app')}>按应用</button>
          <button className={view === 'dev' ? 'on' : ''} onClick={() => setView('dev')}>按网卡</button>
        </div>
      </div>
      <ErrorBanner error={error}/>
      {data?.udpMode === 'need-priv' && (
        <div className="banner warn">
          <div>
            <b>UDP / QUIC 流量还没有计入</b>
            <div className="dim">内核不提供逐套接字的 UDP 字节数，需要以 root 运行 bpftrace 探针（只读观测 UDP 收发，不改任何网络配置）。授权后开始计入，离开本页约半分钟探针自动卸载。</div>
            {authErr && <div style={{color: 'var(--crit)', marginTop: 4}}>{authErr}</div>}
          </div>
          <span className="sp"/>
          <button className="btn primary" disabled={busy} onClick={auth}>{busy ? '等待系统授权…' : '授权统计 UDP'}</button>
        </div>
      )}
      {data?.udpMode === 'error' && <div className="banner warn"><div><b>UDP 流量未计入</b><div className="dim" style={{overflowWrap: 'anywhere'}}>{data.udpError}</div></div></div>}
      {unknown && <div className="banner warn">部分连接属于其他用户（如 root）的进程，普通权限下看不到归属，归在「未知」里。{isRemote() ? '远程登录用户能以 root / sudo 执行后会补全。' : '在「防火墙」页授权后会补全。'}</div>}

      {view === 'app' && <div className="card tbl-wrap">
        <table>
          <thead><tr>{th('name', '应用', false)}<th>使用的网卡</th>{th('conns', '连接')}
            {th('rx', '下行')}{th('tx', '上行')}<th>趋势</th>{th('rxTotal', '累计收')}{th('txTotal', '累计发')}</tr></thead>
          <tbody>{apps.map(a => (
            <Fragment key={a.name}>
              <tr className={'clickable' + (open === a.name ? ' sel' : '') + (a.conns || rate(a) > 0 ? '' : ' off')} onClick={() => setOpen(open === a.name ? null : a.name)}>
                <td>{a.name ? <b>{a.name}</b> : <span className="muted">{appLabel('')}</span>}
                  {a.procs.length > 1 && <span className="muted"> ×{a.procs.length}</span>}</td>
                <td>{a.ifaces.filter(i => i.conns > 0 || total(i) > 0).map(i => <span key={ifKey(i)} style={{marginRight: 4}}><IfaceTag i={i}/></span>)}
                  {!a.ifaces.length && <span className="muted">{a.listens ? `仅监听 ${a.listens} 个端口` : a.udp ? `仅 UDP ×${a.udp}` : '—'}</span>}</td>
                <td className="right num">{a.conns}</td>
                <td className="right num nowrap">{fmtRate(a.rxRate)}</td>
                <td className="right num nowrap">{fmtRate(a.txRate)}</td>
                <td><Spark values={hist.current.get(a.name) || []} color="var(--rx)"/></td>
                <td className="right num nowrap">{fmtBytes(a.rxTotal)}</td>
                <td className="right num nowrap">{fmtBytes(a.txTotal)}</td>
              </tr>
              {open === a.name && <tr className="detail"><td colSpan={8}><AppDetail app={a} socks={Array.isArray(socks.data) ? socks.data : []} udpOn={udpOn}/></td></tr>}
            </Fragment>
          ))}</tbody>
        </table>
        {data && !apps.length && <div className="empty">没有匹配的应用</div>}
        {!data && !error && <div className="empty">采样中…</div>}
      </div>}

      {view === 'dev' && <div className="stack">
        {devs.map(d => (
          <div className="card" key={d.dev}>
            <div className="card-head">
              <h2>{d.dev || '未知网卡'}</h2>
              <span className="muted">{d.apps.length} 个应用 · {d.conns} 条连接</span>
              <span className="sp"/>
              <span className="dim num">下行 {fmtRate(d.rxRate)} · 上行 {fmtRate(d.txRate)} · 累计收 {fmtBytes(d.rxTotal)} / 发 {fmtBytes(d.txTotal)}</span>
            </div>
            <div className="tbl-wrap"><table>
              <thead><tr>{th('name', '应用', false)}<th>对端</th>{th('conns', '连接')}{th('rx', '下行')}{th('tx', '上行')}{th('rxTotal', '累计收')}{th('txTotal', '累计发')}</tr></thead>
              <tbody>{d.apps.map(({app, i}) => (
                <tr key={app.name + ifKey(i)} className={i.conns || rate(i) > 0 ? '' : 'off'}>
                  <td>{app.name ? <b>{app.name}</b> : <span className="muted">{appLabel('')}</span>}</td>
                  <td>{i.via ? <span className="tag">本机 {i.via}</span> : <span className="muted">{d.dev === 'lo' ? '本机' : '外部'}</span>}</td>
                  <td className="right num">{i.conns}</td>
                  <td className="right num nowrap">{fmtRate(i.rxRate)}</td><td className="right num nowrap">{fmtRate(i.txRate)}</td>
                  <td className="right num nowrap">{fmtBytes(i.rxTotal)}</td><td className="right num nowrap">{fmtBytes(i.txTotal)}</td>
                </tr>))}</tbody>
            </table></div>
          </div>
        ))}
        {data && !devs.length && <div className="card empty">没有流量</div>}
      </div>}
    </div>
  )
}
