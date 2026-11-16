import {useEffect, useMemo, useRef, useState} from 'react'
import {Socket, usePoll} from '../api'
import {ErrorBanner} from '../App'
import {fmtBytes, fmtRate} from '../format'

type Tab = 'conn' | 'listen'
const keyOf = (s: Socket) => `${s.proto}|${s.local}:${s.localPort}|${s.peer}:${s.peerPort}`
const isListen = (s: Socket) => s.state === 'LISTEN' || (s.proto === 'udp' && s.state === 'UNCONN')

function scope(addr: string): string {
  if (addr === '*' || addr === '0.0.0.0' || addr === '::') return '所有地址'
  if (addr.startsWith('127.') || addr === '::1') return '仅本机'
  return '指定地址'
}

export default function Connections() {
  const {data, error} = usePoll<Socket[]>('/api/sockets', 2000)
  const [tab, setTab] = useState<Tab>('conn')
  const [q, setQ] = useState('')
  const prev = useRef<{t: number; m: Map<string, Socket>}>({t: 0, m: new Map()})
  const [speed, setSpeed] = useState<Map<string, {up: number; down: number}>>(new Map())

  // TCP 套接字自带累计字节数，相邻两次轮询之差就是这条连接的速率。
  useEffect(() => {
    if (!data) return
    const now = Date.now(), p = prev.current, dt = (now - p.t) / 1000
    const m = new Map<string, Socket>(), sp = new Map<string, {up: number; down: number}>()
    for (const s of data) {
      const k = keyOf(s)
      m.set(k, s)
      const o = p.m.get(k)
      if (o && dt > 0 && dt < 10) sp.set(k, {up: Math.max(0, s.bytesSent - o.bytesSent) / dt, down: Math.max(0, s.bytesRecv - o.bytesRecv) / dt})
    }
    prev.current = {t: now, m}
    setSpeed(sp)
  }, [data])

  const match = (s: Socket) => !q || `${s.app} ${s.dev} ${s.process} ${s.pid} ${s.local}:${s.localPort} ${s.peer}:${s.peerPort} ${s.proto} ${s.iface}`.toLowerCase().includes(q.toLowerCase())
  const all = data || []
  const listens = useMemo(() => all.filter(isListen).filter(match).sort((a, b) => Number(a.localPort) - Number(b.localPort)), [all, q])
  const conns = useMemo(() => all.filter(s => !isListen(s)).filter(match)
    .sort((a, b) => (b.bytesSent + b.bytesRecv) - (a.bytesSent + a.bytesRecv)), [all, q])
  const unknown = all.some(s => !s.pid)

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>连接</h1><p>逐条连接与监听端口。按应用汇总的流量见「应用」页</p></div>
        <span className="sp"/>
        <input type="search" placeholder="按进程 / 地址 / 端口过滤" value={q} onChange={e => setQ(e.target.value)} style={{width: 230}}/>
      </div>
      <ErrorBanner error={error}/>
      {unknown && <div className="banner warn">部分套接字属于其他用户（如 root）的进程，普通权限下看不到归属。在「防火墙」页授权后这里会补全。</div>}
      <div className="tabs">
        <button className={tab === 'conn' ? 'on' : ''} onClick={() => setTab('conn')}>活动连接（{conns.length}）</button>
        <button className={tab === 'listen' ? 'on' : ''} onClick={() => setTab('listen')}>监听端口（{listens.length}）</button>
      </div>
      <div className="card tbl-wrap">
        {tab === 'conn' && <table>
          <thead><tr><th>协议</th><th>应用</th><th>网卡</th><th>本地</th><th>远端</th><th>状态</th>
            <th className="right">下行</th><th className="right">上行</th><th className="right">累计收</th><th className="right">累计发</th></tr></thead>
          <tbody>{conns.slice(0, 500).map(s => {
            const sp = speed.get(keyOf(s))
            return (
              <tr key={keyOf(s)}>
                <td>{s.proto.toUpperCase()}</td>
                <td>{s.pid ? <>{s.app || s.process} <span className="muted">{s.pid}</span></> : <span className="muted">未知</span>}</td>
                <td>{s.dev ? <span className="tag">{s.dev}</span> : <span className="muted">—</span>}</td>
                <td><code>{s.local}:{s.localPort}</code></td>
                <td><code>{s.peer}:{s.peerPort}</code></td>
                <td className="muted">{s.state}</td>
                <td className="right num nowrap">{sp ? fmtRate(sp.down) : ''}</td><td className="right num nowrap">{sp ? fmtRate(sp.up) : ''}</td>
                <td className="right num nowrap">{s.proto === 'tcp' ? fmtBytes(s.bytesRecv) : ''}</td>
                <td className="right num nowrap">{s.proto === 'tcp' ? fmtBytes(s.bytesSent) : ''}</td>
              </tr>)
          })}</tbody>
        </table>}
        {tab === 'listen' && <table>
          <thead><tr><th>协议</th><th className="right">端口</th><th>监听地址</th><th>可达范围</th><th>进程</th></tr></thead>
          <tbody>{listens.map((s, i) => (
            <tr key={keyOf(s) + i}>
              <td>{s.proto.toUpperCase()}</td>
              <td className="right num"><b>{s.localPort}</b></td>
              <td><code>{s.local}</code>{s.iface && <> <span className="tag">{s.iface}</span></>}</td>
              <td><span className={'badge ' + (scope(s.local) === '仅本机' ? 'good' : scope(s.local) === '所有地址' ? 'warn' : 'info')}>{scope(s.local)}</span></td>
              <td>{s.process ? <>{s.process} <span className="muted">{s.pid}</span></> : <span className="muted">未知</span>}</td>
            </tr>))}</tbody>
        </table>}
        {tab === 'conn' && conns.length > 500 && <div className="empty">仅显示流量最大的 500 条，共 {conns.length} 条</div>}
        {data && !all.length && <div className="empty">没有套接字</div>}
      </div>
    </div>
  )
}
