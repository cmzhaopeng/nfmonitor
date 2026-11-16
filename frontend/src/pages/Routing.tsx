import {useMemo, useState} from 'react'
import {getJSON, RouteGet, Routing, Rule, usePoll} from '../api'
import {ErrorBanner} from '../App'

const ACTION_LABEL: Record<string, string> = {unreachable: '不可达', blackhole: '黑洞', prohibit: '禁止', nop: '空操作', goto: '跳转'}

export function RuleRow({r, sel, hit, onClick}: {r: Rule; sel?: boolean; hit?: boolean; onClick?: () => void}) {
  return (
    <div className={'rule-row' + (onClick && r.action === 'lookup' ? ' clickable' : '') + (sel ? ' sel' : '') + (hit ? ' hit' : '')} onClick={onClick}>
      <span className="num muted right">{r.priority}</span>
      <code>{r.text}</code>
      {r.action === 'lookup' ? <span className="tag">→ 表 {r.table}</span>
        : <span className="tag">{ACTION_LABEL[r.action] || r.action}{r.action === 'goto' ? ` ${r.goto}` : ''}</span>}
    </div>
  )
}

export default function RoutingPage() {
  const {data, error} = usePoll<Routing>('/api/routing', 5000)
  const [fam, setFam] = useState<'inet' | 'inet6'>('inet')
  const [table, setTable] = useState('main')
  const [dst, setDst] = useState('')
  const [res, setRes] = useState<RouteGet | null>(null)
  const [resErr, setResErr] = useState('')
  const [busy, setBusy] = useState(false)

  const rules = useMemo(() => (data?.rules || []).filter(r => r.family === fam), [data, fam])
  const tables = data?.tables || []
  const cur = tables.find(t => t.id === table)
  const routes = (cur?.routes || []).filter(r => r.family === fam)

  const lookup = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!dst.trim()) return
    setBusy(true); setResErr('')
    try {
      const r = await getJSON<RouteGet>('/api/routeget?dst=' + encodeURIComponent(dst.trim()))
      setRes(r); setTable(r.table)
      setFam(r.dst.includes(':') ? 'inet6' : 'inet')
    } catch (err: any) { setRes(null); setResErr(String(err.message || err)) }
    setBusy(false)
  }

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>路由</h1><p>内核按优先级从小到大逐条匹配策略规则，命中后去对应的路由表里找出口</p></div>
        <span className="sp"/>
        <div className="seg">
          <button className={fam === 'inet' ? 'on' : ''} onClick={() => setFam('inet')}>IPv4</button>
          <button className={fam === 'inet6' ? 'on' : ''} onClick={() => setFam('inet6')}>IPv6</button>
        </div>
      </div>
      <ErrorBanner error={error}/>

      <div className="card">
        <form className="card-head" onSubmit={lookup} style={{marginBottom: res || resErr ? 10 : 0}}>
          <h2>出口测试</h2>
          <input type="text" placeholder="IP 或域名，例如 8.8.8.8" value={dst} onChange={e => setDst(e.target.value)} style={{width: 260}}/>
          <button className="btn primary" disabled={busy}>{busy ? '查询中…' : '这个地址怎么走？'}</button>
          <span className="muted">等价于 <code>ip route get</code>，按当前进程的身份查询</span>
        </form>
        {resErr && <div className="banner err" style={{margin: 0}}>{resErr}</div>}
        {res && (
          <div className="flow">
            <div className="node"><span className="k">目的地址</span><span className="v">{res.dst}</span></div>
            <span className="arrow">→</span>
            <div className="node hl"><span className="k">命中路由表</span><span className="v">{res.table}</span></div>
            <span className="arrow">→</span>
            <div className="node"><span className="k">出口网卡</span><span className="v">{res.dev || '—'}</span><span className="s">源地址 {res.prefsrc || '—'}</span></div>
            <span className="arrow">→</span>
            <div className="node"><span className="k">下一跳</span><span className="v">{res.gateway || (res.type === 'local' ? '本机' : '直连')}</span></div>
          </div>
        )}
      </div>

      <div className="grid two">
        <div className="card">
          <div className="card-head"><h2>策略规则</h2><span className="muted">{rules.length} 条 · 点击规则查看它指向的表</span></div>
          <div className="rule-list">
            {rules.map((r, i) => (
              <RuleRow key={i} r={r} sel={r.action === 'lookup' && r.table === table} hit={!!res && r.action === 'lookup' && r.table === res.table}
                       onClick={r.action === 'lookup' ? () => setTable(r.table) : undefined}/>
            ))}
            {!rules.length && <div className="empty">没有规则</div>}
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <h2>路由表</h2>
            <select value={table} onChange={e => setTable(e.target.value)}>
              {tables.map(t => <option key={t.id} value={t.id}>{t.id}{t.name && t.name !== t.id ? ` (${t.name})` : ''} · {t.routes.filter(r => r.family === fam).length} 条</option>)}
              {!cur && <option value={table}>{table} · 空</option>}
            </select>
            <span className="muted">{table === 'local' ? '本机地址与广播，内核自动维护' : table === 'main' ? '常规路由' : ''}</span>
          </div>
          <div className="tbl-wrap" style={{maxHeight: '62vh'}}>
            <table>
              <thead><tr><th>目的</th><th>下一跳</th><th>出口</th><th>来源</th><th className="right">跃点</th></tr></thead>
              <tbody>
              {routes.map((r, i) => (
                <tr key={i} className={r.flags.includes('linkdown') ? 'off' : ''}>
                  <td><code>{r.dst === 'default' ? 'default（默认）' : r.dst}</code>{r.type && <> <span className="tag">{r.type}</span></>}</td>
                  <td><code>{r.gateway || '直连'}</code></td>
                  <td>{r.dev}{r.flags.includes('linkdown') && <span className="muted">（未连接）</span>}</td>
                  <td className="muted">{r.protocol}</td>
                  <td className="right num">{r.metric || ''}</td>
                </tr>
              ))}
              </tbody>
            </table>
            {!routes.length && <div className="empty">该表没有 {fam === 'inet' ? 'IPv4' : 'IPv6'} 路由</div>}
          </div>
        </div>
      </div>
    </div>
  )
}
