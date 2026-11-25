import {useMemo, useState} from 'react'
import {canWrite, elevate, Firewall, FwChain, FwTable, Meta, usePoll} from '../api'
import {ErrorBanner} from '../App'
import {fmtBytes, fmtCount} from '../format'
import UfwPanel from './Ufw'
import FirewalldPanel from './Firewalld'

type Tab = 'hooks' | 'tables' | 'ufw' | 'firewalld' | 'raw'
interface Ref { table: FwTable; chain: FwChain }
const refKey = (r: Ref) => `${r.table.family}|${r.table.name}|${r.chain.name}`

const HOOKS = ['prerouting', 'input', 'forward', 'output', 'postrouting'] as const
const HOOK_DESC: Record<string, string> = {
  prerouting: '包刚进来，路由判决之前', input: '目的地是本机', forward: '经本机转发', output: '本机进程发出', postrouting: '即将离开本机',
  ingress: '网卡入口（最早）', egress: '网卡出口（最晚）',
}
const BACKEND_LABEL: Record<string, string> = {nft: 'nftables', 'iptables-nft': 'iptables（nft 后端）', 'iptables-legacy': 'iptables（legacy）'}
const RAW_LABEL: Record<string, string> = {
  nft: 'nft list ruleset', ufw: 'ufw status verbose', 'ufw-numbered': 'ufw status numbered', 'iptables-save': 'iptables-save', 'ip6tables-save': 'ip6tables-save',
  'iptables-legacy-save': 'iptables-legacy-save', 'ip6tables-legacy-save': 'ip6tables-legacy-save',
  'firewalld-zones': 'firewall-cmd --list-all-zones',
}
const RAW_ORDER = ['ufw', 'ufw-numbered', 'firewalld-zones', 'nft', 'iptables-save', 'ip6tables-save', 'iptables-legacy-save', 'ip6tables-legacy-save']

function PolicyBadge({c}: {c: FwChain}) {
  if (!c.base) return null
  return <span className={'badge ' + (c.policy === 'drop' ? 'crit' : 'good')}>默认{c.policy === 'drop' ? '丢弃' : '放行'}</span>
}

const KW = /\b(ip6?|tcp|udp|icmp(?:v6)?|meta|ct|iifname|oifname|iif|oif|saddr|daddr|sport|dport|state|mark|fib|limit|log|xt)\b/g
function RuleText({text}: {text: string}) {
  const parts = text.split(KW)
  return <span className="rule-text">{parts.map((p, i) => i % 2 ? <span key={i} className="kw">{p}</span> : p)}</span>
}

function ChainDetail({r, all, onJump}: {r: Ref; all: Ref[]; onJump: (r: Ref) => void}) {
  const {table, chain} = r
  const callers = all.filter(x => x.table === table && x.chain.rules.some(ru => ru.target === chain.name))
  const anyCounter = chain.rules.some(x => x.hasCounter)
  return (
    <div className="card">
      <div className="card-head">
        <h2><code style={{fontSize: 14}}>{table.family} {table.name} / {chain.name}</code></h2>
        <span className="tag">{BACKEND_LABEL[table.backend] || table.backend}</span>
        {(chain.owner || table.owner) && <span className="badge plain">{chain.owner || table.owner}</span>}
        <PolicyBadge c={chain}/>
      </div>
      <div className="dim" style={{marginBottom: 10}}>
        {chain.base
          ? <>基链：挂在 <b>{chain.hook}</b> hook{chain.device && <>（设备 {chain.device}）</>}，类型 {chain.type}，优先级 {chain.priority}{String(chain.prio) !== chain.priority && <>（{chain.prio}）</>}。没有规则命中时{chain.policy === 'drop' ? '丢弃' : '放行'}。</>
          : <>普通链：只有被别的链 jump / goto 时才执行。
            {callers.length ? <> 调用方：{callers.map(c => <button key={refKey(c)} className="link" style={{marginRight: 8}} onClick={() => onJump(c)}>{c.chain.name}</button>)}</> : ' 目前没有链引用它。'}</>}
      </div>
      {chain.rules.length ? (
        <div className="tbl-wrap"><table>
          <thead><tr><th className="right">#</th><th>匹配条件</th><th>动作</th>{anyCounter && <><th className="right">包</th><th className="right">字节</th></>}<th>备注</th></tr></thead>
          <tbody>
          {chain.rules.map((ru, i) => {
            const tgt = ru.target ? all.find(x => x.table === table && x.chain.name === ru.target) : undefined
            return (
              <tr key={i} className={ru.hasCounter && ru.packets === 0 ? 'off' : ''}>
                <td className="right num muted">{i + 1}</td>
                <td>{ru.text === [ru.verdict, ru.target].filter(Boolean).join(' ') ? <span className="muted">所有包</span> : <RuleText text={ru.text}/>}</td>
                <td className="nowrap">
                  {ru.verdict && <span className={'verdict ' + ru.verdict}>{ru.verdict}</span>}
                  {ru.target && <> {tgt ? <button className="link" onClick={() => onJump(tgt)}>{ru.target}</button> : <code>{ru.target}</code>}</>}
                </td>
                {anyCounter && <>
                  <td className="right num">{ru.hasCounter ? fmtCount(ru.packets) : ''}</td>
                  <td className="right num nowrap">{ru.hasCounter ? fmtBytes(ru.bytes) : ''}</td>
                </>}
                <td className="dim">{ru.comment}</td>
              </tr>
            )
          })}
          </tbody>
        </table></div>
      ) : <div className="empty">这条链是空的{chain.base ? `，所有包按默认策略${chain.policy === 'drop' ? '丢弃' : '放行'}` : ''}</div>}
    </div>
  )
}

export default function FirewallPage({onPrivChange, meta}: {onPrivChange: () => void; meta: Meta | null}) {
  const remote = !!meta?.remote
  const {data, error, loading, reload} = usePoll<Firewall>('/api/firewall', 10000)
  const [tab, setTab] = useState<Tab>('hooks')
  const [selKey, setSelKey] = useState('')
  const [q, setQ] = useState('')
  const [rawKey, setRawKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [authErr, setAuthErr] = useState('')

  const all = useMemo<Ref[]>(() => (data?.tables || []).flatMap(t => t.chains.map(c => ({table: t, chain: c}))), [data])
  const sel = all.find(r => refKey(r) === selKey)
  const select = (r: Ref) => setSelKey(refKey(r))
  const byHook = (h: string) => all.filter(r => r.chain.base && r.chain.hook === h).sort((a, b) => a.chain.prio - b.chain.prio)
  const otherHooks = [...new Set(all.filter(r => r.chain.base && !HOOKS.includes(r.chain.hook as any)).map(r => r.chain.hook))]
  const ql = q.trim().toLowerCase()
  const hits = useMemo(() => !ql ? [] : all.flatMap(r => r.chain.rules
    .filter(ru => `${ru.text} ${ru.comment} ${ru.verdict} ${ru.target}`.toLowerCase().includes(ql)).map(ru => ({r, ru}))), [all, ql])
  const raws = RAW_ORDER.filter(k => data?.raw[k] != null)
  const curRaw = raws.includes(rawKey) ? rawKey : raws[0]
  const totalRules = all.reduce((n, r) => n + r.chain.rules.length, 0)

  const auth = async () => {
    setBusy(true); setAuthErr('')
    try { await elevate(); onPrivChange(); reload() } catch (e: any) { setAuthErr(String(e.message || e)) }
    setBusy(false)
  }

  const HookCard = ({h, cls = ''}: {h: string; cls?: string}) => {
    const cs = byHook(h)
    return (
      <div className={'hook ' + cls}>
        <div className="t"><b>{h.toUpperCase()}</b><span className="muted" style={{fontSize: 11}}>{HOOK_DESC[h]}</span></div>
        {cs.map(r => (
          <button key={refKey(r)} className={'hchain' + (refKey(r) === selKey ? ' sel' : '')} onClick={() => select(r)}
                  title={`${r.table.family} ${r.table.name} / ${r.chain.name} · 优先级 ${r.chain.priority}`}>
            <div className="l1"><span className="p">{r.chain.prio}</span><span className="n">{r.table.name}/{r.chain.name}</span></div>
            <div className="l2">
              <span className="tag">{r.table.family}</span><span className="tag">{r.chain.type}</span>
              <span className="tag">{r.chain.rules.length} 条</span>
              {r.chain.policy === 'drop' && <span className="badge crit">默认丢弃</span>}
              {(r.chain.owner || r.table.owner) && <span className="badge plain">{r.chain.owner || r.table.owner}</span>}
            </div>
          </button>
        ))}
        {!cs.length && <div className="muted" style={{fontSize: 12, padding: '4px 2px'}}>没有链挂在这里</div>}
      </div>
    )
  }

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>防火墙</h1><p>nftables、iptables、ufw、docker 等装的规则最终都落在 netfilter 的几个 hook 上，这里按内核实际执行顺序统一展示</p></div>
        <span className="sp"/>
        {data?.privileged && <>
          {data.tools.ufw && <span className={'badge ' + (data.ufwStatus === 'active' ? 'good' : 'warn')}>ufw {data.ufwStatus === 'active' ? '已启用' : data.ufwStatus === 'inactive' ? '未启用' : '状态未知'}</span>}
          {data.firewalld && <span className={'badge ' + (data.firewalld.state === 'running' ? 'good' : 'warn')}>firewalld {data.firewalld.state === 'running' ? '运行中' : '未运行'}</span>}
          <span className="muted">{data.tables.length} 张表 · {all.length} 条链 · {totalRules} 条规则</span>
          <button className="btn" onClick={reload}>刷新</button>
        </>}
      </div>
      <ErrorBanner error={error}/>

      {data && !data.privileged && remote && (
        <div className="banner warn">
          <div>
            <b>读取远程主机的防火墙规则需要 root 权限</b>
            <div className="dim">{meta?.rootErr || '请用 root 登录，或为登录用户配置 sudo（免密，或在「主机管理」里填写 sudo 口令）。'}</div>
          </div>
        </div>
      )}
      {data && !data.privileged && !remote && (
        <div className="banner warn">
          <div>
            <b>读取防火墙规则需要 root 权限</b>
            <div className="dim">授权后会以 root 启动一个助手：执行固定的查看命令（nft list ruleset、iptables-save、ufw status、ss）和「应用」页统计 UDP 流量用的 bpftrace 探针；只有你在「ufw 策略」页确认修改时才会改动 ufw 规则，且不再重复询问密码。关闭程序即退出。</div>
            {authErr && <div style={{color: 'var(--crit)', marginTop: 4}}>{authErr}</div>}
            {data.errors.nft && !/尚未授权/.test(data.errors.nft) && <div style={{color: 'var(--crit)', marginTop: 4}}>{data.errors.nft}</div>}
          </div>
          <span className="sp"/>
          <button className="btn primary" disabled={busy} onClick={auth}>{busy ? '等待系统授权…' : '授权读取'}</button>
        </div>
      )}
      {data && !data.privileged && <div className="card dim">
        已检测到：{Object.entries(data.tools).map(([k, v]) => <span className="tag" key={k} style={{marginRight: 6}}>{v === 'installed' ? k : v}</span>)}
        {/nf_tables/.test(data.tools.iptables || '') && <div style={{marginTop: 6}}>本机 iptables 使用 nf_tables 后端：iptables / ufw 写入的规则与原生 nft 规则在同一份 ruleset 里，授权后可以一起看。</div>}
      </div>}
      {loading && !data && <div className="empty">读取中…</div>}

      {data?.privileged && <>
        <div className="tabs">
          <button className={tab === 'hooks' ? 'on' : ''} onClick={() => setTab('hooks')}>Hook 流程</button>
          <button className={tab === 'tables' ? 'on' : ''} onClick={() => setTab('tables')}>表与链</button>
          {data.ufw && <button className={tab === 'ufw' ? 'on' : ''} onClick={() => setTab('ufw')}>ufw 策略</button>}
          {data.firewalld && <button className={tab === 'firewalld' ? 'on' : ''} onClick={() => setTab('firewalld')}>firewalld 区域</button>}
          <button className={tab === 'raw' ? 'on' : ''} onClick={() => setTab('raw')}>原始输出</button>
          <span style={{flex: 1}}/>
          {(tab === 'hooks' || tab === 'tables') && <input type="search" placeholder="搜索规则：端口、地址、链名…" value={q} onChange={e => setQ(e.target.value)} style={{width: 240, marginBottom: 6}}/>}
        </div>

        {(tab === 'hooks' || tab === 'tables') && ql && (
          <div className="card" style={{marginBottom: 12}}>
            <div className="card-head"><h2>搜索结果</h2><span className="muted">{hits.length} 条规则匹配「{q.trim()}」</span></div>
            <div className="tbl-wrap" style={{maxHeight: 280}}><table><tbody>
              {hits.slice(0, 200).map(({r, ru}, i) => (
                <tr key={i} className="clickable" onClick={() => select(r)}>
                  <td className="nowrap"><code>{r.table.family} {r.table.name}/{r.chain.name}</code></td>
                  <td><RuleText text={ru.text}/></td>
                  <td>{ru.verdict && <span className={'verdict ' + ru.verdict}>{ru.verdict}</span>} {ru.target && <code>{ru.target}</code>}</td>
                </tr>
              ))}
            </tbody></table></div>
            {!hits.length && <div className="empty">没有匹配的规则</div>}
          </div>
        )}

        {tab === 'hooks' && <div className="stack">
          <div className="card">
            <div className="card-head"><h2>包经过的 hook</h2><span className="muted">每个 hook 内按优先级从小到大执行（数字越小越先）；点一条链查看规则</span></div>
            <div className="hooks">
              <HookCard h="prerouting"/>
              <HookCard h="input"/>
              <div className="hook proc"><b>本机进程</b><span style={{fontSize: 11}}>套接字收发</span></div>
              <HookCard h="output"/>
              <HookCard h="postrouting" cls="last"/>
              <HookCard h="forward" cls="fwd"/>
            </div>
            <div className="muted" style={{marginTop: 8}}>入站：PREROUTING → INPUT → 进程；出站：进程 → OUTPUT → POSTROUTING；转发：PREROUTING → FORWARD → POSTROUTING。</div>
            {otherHooks.length > 0 && <div className="hooks" style={{marginTop: 10}}>{otherHooks.map(h => <HookCard key={h} h={h} cls="last"/>)}</div>}
          </div>
          {sel ? <ChainDetail r={sel} all={all} onJump={select}/> : all.length > 0 && <div className="card empty">点上面的任意一条链查看它的规则</div>}
          {!all.length && <div className="card empty">ruleset 是空的：本机没有任何 netfilter 规则，所有流量默认放行</div>}
        </div>}

        {tab === 'tables' && <div className="fw-cols">
          <div className="card tree">
            {data.tables.map(t => (
              <div key={t.family + t.name} style={{marginBottom: 8}}>
                <div className="tb"><code>{t.family} {t.name}</code>{t.owner && <span className="badge plain">{t.owner}</span>}
                  <span className="muted" style={{fontWeight: 400, fontSize: 11}}>{BACKEND_LABEL[t.backend] || t.backend}</span></div>
                {t.chains.map(c => {
                  const r = {table: t, chain: c}
                  return (
                    <button key={c.name} className={'ch' + (refKey(r) === selKey ? ' sel' : '')} onClick={() => select(r)}>
                      <span className="n">{c.name}</span>
                      {c.base && <span className="tag">{c.hook}</span>}
                      <span className="muted num">{c.rules.length}</span>
                    </button>
                  )
                })}
                {t.objects.map(o => <div key={o.kind + o.name} className="muted" style={{padding: '2px 6px 2px 18px', fontSize: 12}}>{o.kind} <code>{o.name}</code></div>)}
                {!t.chains.length && !t.objects.length && <div className="muted" style={{padding: '2px 18px'}}>空表</div>}
              </div>
            ))}
            {!data.tables.length && <div className="empty">没有表</div>}
          </div>
          <div>{sel ? <ChainDetail r={sel} all={all} onJump={select}/> : <div className="card empty">从左侧选择一条链</div>}</div>
        </div>}

        {(tab === 'ufw' || tab === 'firewalld') && !canWrite() && <div className="banner warn">只读账号：可以查看规则，不能修改。</div>}
        <fieldset disabled={!canWrite()} style={{border: 0, padding: 0, margin: 0, minWidth: 0}}>
          {tab === 'ufw' && data.ufw && <UfwPanel ufw={data.ufw} onChanged={reload}/>}
          {tab === 'firewalld' && data.firewalld && <FirewalldPanel info={data.firewalld} onChanged={reload}/>}
        </fieldset>

        {tab === 'raw' && <div className="card">
          <div className="card-head">
            <div className="seg">{raws.map(k => <button key={k} className={k === curRaw ? 'on' : ''} onClick={() => setRawKey(k)}>{RAW_LABEL[k] || k}</button>)}</div>
            <span className="sp"/>
            {curRaw && <button className="btn" onClick={() => navigator.clipboard?.writeText(data.raw[curRaw])}>复制</button>}
          </div>
          {curRaw ? <pre className="raw">{data.raw[curRaw].trim() || '（输出为空）'}</pre> : <div className="empty">没有可显示的输出</div>}
          {Object.entries(data.errors).filter(([k]) => !/legacy/.test(k)).map(([k, v]) => <div key={k} className="muted" style={{marginTop: 6}}>{RAW_LABEL[k] || k} 失败：{v}</div>)}
        </div>}
      </>}
    </div>
  )
}
