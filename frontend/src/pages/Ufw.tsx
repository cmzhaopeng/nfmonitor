import {useEffect, useMemo, useState} from 'react'
import {Link, UfwInfo, UfwOp, UfwResult, UfwRule, ufwApply, ufwPreview, usePoll} from '../api'

// ufw 策略管理：像硬件防火墙的 Web 界面一样按表格增删改规则、设置默认策略。
// 每次修改先预览将要执行的 ufw 命令，确认后由后端经 pkexec 以 root 执行。

const ACTION: Record<string, {label: string; cls: string; desc: string}> = {
  allow: {label: '允许', cls: 'good', desc: '放行'},
  deny: {label: '丢弃', cls: 'crit', desc: '静默丢弃，对方只能等超时'},
  reject: {label: '拒绝', cls: 'warn', desc: '丢弃并回复拒绝，对方立即知道不通'},
  limit: {label: '限速', cls: 'info', desc: '允许，但同一地址 30 秒内连接 6 次以上就拒绝（防暴力破解）'},
}
const POLICY: Record<string, string> = {allow: '允许', deny: '丢弃', reject: '拒绝'}
const LOGGING: Record<string, string> = {off: '关闭', low: '低', medium: '中', high: '高', full: '全部'}
const PROTOS = [['any', '任意'], ['tcp', 'TCP'], ['udp', 'UDP'], ['esp', 'ESP'], ['ah', 'AH'], ['gre', 'GRE']]

type Kind = 'in' | 'out' | 'route'
const kindOf = (r: UfwRule): Kind => r.route ? 'route' : r.dir
const KIND_LABEL: Record<Kind, string> = {in: '入站', out: '出站', route: '转发'}

interface Group { key: string; rules: UfwRule[]; r: UfwRule; nums: number[] }

function groupRules(rules: UfwRule[]): Group[] {
  // ufw 对「任意地址」的规则会各写一条 v4、v6，spec 相同；合并成一行，删除时一起删。
  const m = new Map<string, Group>()
  for (const r of rules) {
    const key = (r.route ? 'route ' : '') + r.spec.join(' ')
    const g = m.get(key)
    if (g) { g.rules.push(r); if (r.num) g.nums.push(r.num) } else m.set(key, {key, rules: [r], r, nums: r.num ? [r.num] : []})
  }
  return [...m.values()].sort((a, b) => (a.nums[0] ?? 1e9) - (b.nums[0] ?? 1e9))
}

const Any = () => <span className="muted">任意</span>
const val = (v: string) => !v || v === 'any' ? <Any/> : <code>{v}</code>

function IfaceCell({r}: {r: UfwRule}) {
  if (r.route) {
    if (!r.ifaceIn && !r.ifaceOut) return <Any/>
    return <span className="nowrap">{r.ifaceIn ? <code>{r.ifaceIn}</code> : <Any/>} → {r.ifaceOut ? <code>{r.ifaceOut}</code> : <Any/>}</span>
  }
  const i = r.dir === 'in' ? r.ifaceIn : r.ifaceOut
  return i ? <code>{i}</code> : <Any/>
}

function ActionBadge({r}: {r: Pick<UfwRule, 'action'>}) {
  const a = ACTION[r.action] || {label: r.action, cls: ''}
  return <span className={'badge ' + a.cls}>{a.label}</span>
}

// ---------- 修改的预览 / 执行 ----------

function useOpPreview(op: UfwOp | null) {
  const [cmds, setCmds] = useState<string[][]>([])
  const [err, setErr] = useState('')
  const key = JSON.stringify(op)
  useEffect(() => {
    if (!op) return
    let live = true
    const t = setTimeout(() => {
      ufwPreview(op).then(r => { if (live) { setCmds(r.commands); setErr('') } })
        .catch(e => { if (live) { setCmds([]); setErr(String(e.message || e)) } })
    }, 200)
    return () => { live = false; clearTimeout(t) }
  }, [key])
  return {cmds, err}
}

function Commands({cmds, err}: {cmds: string[][]; err: string}) {
  if (err === '规则没有变化') return <div className="muted">还没有修改</div>
  if (err) return <div className="form-err">{err}</div>
  if (!cmds.length) return <div className="muted">…</div>
  return <pre className="raw cmd">{cmds.map(c => '$ sudo ' + c.map(a => /[\s'"]/.test(a) || a === '' ? `'${a.replace(/'/g, `'\\''`)}'` : a).join(' ')).join('\n')}</pre>
}

function Modal({title, onClose, children, foot, wide}: {title: string; onClose: () => void; children: React.ReactNode; foot: React.ReactNode; wide?: boolean}) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose])
  return (
    <div className="modal-bg" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
      <div className={'modal' + (wide ? ' wide' : '')} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head"><h2>{title}</h2><span className="sp"/><button className="btn ghost" onClick={onClose} aria-label="关闭">✕</button></div>
        <div className="modal-body">{children}</div>
        <div className="modal-foot">{foot}</div>
      </div>
    </div>
  )
}

function useApply(onDone: (r: UfwResult) => void) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const run = async (op: UfwOp) => {
    setBusy(true); setErr('')
    try { onDone(await ufwApply(op)) } catch (e: any) { setErr(String(e.message || e)) }
    setBusy(false)
  }
  return {busy, err, run}
}

/** 删除、启停、默认策略这类「确认一下就执行」的修改。 */
function ConfirmOp({title, op, children, danger, okText, onClose, onDone}: {
  title: string; op: UfwOp; children?: React.ReactNode; danger?: boolean; okText: string
  onClose: () => void; onDone: (r: UfwResult) => void
}) {
  const pv = useOpPreview(op)
  const ap = useApply(onDone)
  return (
    <Modal title={title} onClose={onClose} foot={<>
      {ap.err && <div className="form-err" style={{flex: 1}}>{ap.err}</div>}
      <span className="sp"/>
      <button className="btn" onClick={onClose}>取消</button>
      <button className={'btn ' + (danger ? 'danger' : 'primary')} disabled={ap.busy || !!pv.err || !pv.cmds.length} onClick={() => ap.run(op)}>
        {ap.busy ? '等待系统授权…' : okText}</button>
    </>}>
      {children}
      <div className="field-label" style={{marginTop: 10}}>将执行</div>
      <Commands {...pv}/>
    </Modal>
  )
}

// ---------- 规则编辑 ----------

interface Draft {
  kind: Kind; action: UfwRule['action']; log: UfwRule['log']; proto: string
  src: string; sport: string; dst: string; dport: string; ifaceIn: string; ifaceOut: string; comment: string
}
const blank: Draft = {kind: 'in', action: 'allow', log: '', proto: 'tcp', src: '', sport: '', dst: '', dport: '', ifaceIn: '', ifaceOut: '', comment: ''}
const fromRule = (r: UfwRule): Draft => ({
  kind: kindOf(r), action: r.action, log: r.log, proto: r.proto,
  src: r.src === 'any' ? '' : r.src, sport: r.sport === 'any' ? '' : r.sport,
  dst: r.dst === 'any' ? '' : r.dst, dport: r.dport === 'any' ? '' : r.dport,
  ifaceIn: r.ifaceIn, ifaceOut: r.ifaceOut, comment: r.comment,
})
const toRule = (d: Draft): Partial<UfwRule> => ({
  route: d.kind === 'route', dir: d.kind === 'out' ? 'out' : 'in', action: d.action, log: d.log, proto: d.proto,
  src: d.src, sport: d.sport, dst: d.dst, dport: d.dport,
  ifaceIn: d.kind === 'out' ? '' : d.ifaceIn, ifaceOut: d.kind === 'in' ? '' : d.ifaceOut, comment: d.comment,
})

function RuleEditor({old, groups, ifaces, onClose, onDone}: {
  old?: Group; groups: Group[]; ifaces: string[]; onClose: () => void; onDone: (r: UfwResult) => void
}) {
  const [d, setD] = useState<Draft>(old ? fromRule(old.r) : blank)
  const [pos, setPos] = useState(0)
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD(x => ({...x, [k]: v}))
  const op: UfwOp = old ? {op: 'replace', old: old.r, rule: toRule(d)} : {op: 'add', rule: toRule(d), position: pos || undefined}
  const pv = useOpPreview(op)
  const ap = useApply(onDone)
  const portless = !['any', 'tcp', 'udp'].includes(d.proto)
  const ifaceInput = (k: 'ifaceIn' | 'ifaceOut', label: string) => (
    <label className="field"><span className="field-label">{label}</span>
      <input type="text" list="ufw-ifaces" placeholder="任意" value={d[k]} onChange={e => set(k, e.target.value.trim())}/></label>
  )
  return (
    <Modal wide title={old ? `编辑规则 #${old.nums.join(', ')}` : '添加规则'} onClose={onClose} foot={<>
      {ap.err && <div className="form-err" style={{flex: 1}}>{ap.err}</div>}
      <span className="sp"/>
      <button className="btn" onClick={onClose}>取消</button>
      <button className="btn primary" disabled={ap.busy || !!pv.err || !pv.cmds.length} onClick={() => ap.run(op)}>{ap.busy ? '等待系统授权…' : '应用'}</button>
    </>}>
      <datalist id="ufw-ifaces">{ifaces.map(i => <option key={i} value={i}/>)}</datalist>
      <div className="form">
        <div className="field"><span className="field-label">方向</span>
          <div className="seg">{(['in', 'out', 'route'] as Kind[]).map(k =>
            <button key={k} className={d.kind === k ? 'on' : ''} onClick={() => set('kind', k)}>{KIND_LABEL[k]}</button>)}</div>
          <span className="hint">{d.kind === 'in' ? '发往本机的连接' : d.kind === 'out' ? '本机发起的连接' : '经本机转发（容器、虚拟机、路由）'}</span>
        </div>
        <div className="field"><span className="field-label">动作</span>
          <div className="seg">{Object.entries(ACTION).map(([k, a]) =>
            <button key={k} className={d.action === k ? 'on' : ''} onClick={() => set('action', k as Draft['action'])}>{a.label}</button>)}</div>
          <span className="hint">{ACTION[d.action].desc}</span>
        </div>
        <label className="field"><span className="field-label">协议</span>
          <select value={d.proto} onChange={e => set('proto', e.target.value)}>{PROTOS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label className="field"><span className="field-label">日志</span>
          <select value={d.log} onChange={e => set('log', e.target.value as Draft['log'])}>
            <option value="">不记录</option><option value="log">记录新连接</option><option value="log-all">记录所有包</option></select></label>

        <div className="form-sec">源</div>
        <label className="field"><span className="field-label">源地址</span>
          <input type="text" placeholder="任意，或 192.168.1.0/24、10.0.0.5、fd00::/8" value={d.src} onChange={e => set('src', e.target.value)}/></label>
        <label className="field"><span className="field-label">源端口</span>
          <input type="text" disabled={portless} placeholder={portless ? '该协议没有端口' : '任意（一般不填）'} value={portless ? '' : d.sport} onChange={e => set('sport', e.target.value)}/></label>
        <div className="form-sec">目的</div>
        <label className="field"><span className="field-label">目的地址</span>
          <input type="text" placeholder={d.kind === 'in' ? '任意（即本机任意地址）' : '任意'} value={d.dst} onChange={e => set('dst', e.target.value)}/></label>
        <label className="field"><span className="field-label">目的端口</span>
          <input type="text" disabled={portless} placeholder={portless ? '该协议没有端口' : '任意，或 22、80,443、6000:6010'} value={portless ? '' : d.dport} onChange={e => set('dport', e.target.value)}/></label>

        <div className="form-sec">网卡与其他</div>
        {d.kind !== 'out' && ifaceInput('ifaceIn', '入网卡')}
        {d.kind !== 'in' && ifaceInput('ifaceOut', '出网卡')}
        {d.kind !== 'route' && old && <span/>}
        {!old && <label className="field"><span className="field-label">位置</span>
          <select value={pos} onChange={e => setPos(+e.target.value)}>
            <option value={0}>追加到末尾</option>
            {groups.filter(g => g.nums.length).map(g => <option key={g.key} value={g.nums[0]}>插到 #{g.nums[0]} 之前：{summary(g.r)}</option>)}
          </select></label>}
        <label className="field span2"><span className="field-label">备注</span>
          <input type="text" maxLength={120} placeholder="可选，例如：办公网 SSH" value={d.comment} onChange={e => set('comment', e.target.value)}/></label>
      </div>
      <div className="hint" style={{marginTop: 8}}>
        ufw 按序号从小到大匹配，第一条命中的规则生效。地址留空表示任意；地址为任意时 ufw 会同时生成 IPv4、IPv6 两条。
        {old && ' 只改动作、日志或备注时原地更新；改了其他条件会先在原位置插入新规则，再删掉旧规则。'}
      </div>
      <div className="field-label" style={{marginTop: 10}}>将执行</div>
      <Commands {...pv}/>
    </Modal>
  )
}

function summary(r: UfwRule) {
  const ep = (a: string, p: string, app: string) => (a === 'any' ? '任意' : a) + (app ? ` (${app})` : p !== 'any' ? `:${p}` : '')
  return `${KIND_LABEL[kindOf(r)]} ${ACTION[r.action]?.label || r.action} ${r.proto !== 'any' ? r.proto + ' ' : ''}${ep(r.src, r.sport, r.sapp)} → ${ep(r.dst, r.dport, r.dapp)}`
}

// ---------- 面板 ----------

type Dialog =
  | {t: 'edit'; g?: Group}
  | {t: 'confirm'; title: string; op: UfwOp; body?: React.ReactNode; danger?: boolean; ok: string}

export default function UfwPanel({ufw, onChanged}: {ufw: UfwInfo; onChanged: () => void}) {
  const links = usePoll<Link[]>('/api/links')
  const [dlg, setDlg] = useState<Dialog | null>(null)
  const [done, setDone] = useState<UfwResult | null>(null)
  const [kind, setKind] = useState<Kind | 'all'>('all')
  const [q, setQ] = useState('')
  const groups = useMemo(() => groupRules(ufw.rules), [ufw.rules])
  const ql = q.trim().toLowerCase()
  const shown = groups.filter(g => (kind === 'all' || kindOf(g.r) === kind) &&
    (!ql || `${summary(g.r)} ${g.r.comment} ${g.r.ifaceIn} ${g.r.ifaceOut} ${g.r.spec.join(' ')}`.toLowerCase().includes(ql)))
  const counts = (k: Kind) => groups.filter(g => kindOf(g.r) === k).length
  const active = ufw.status === 'active'
  const ifaces = (links.data || []).map(l => l.name)

  const finished = (r: UfwResult) => { setDlg(null); setDone(r); onChanged() }
  const close = () => setDlg(null)
  const confirm = (title: string, op: UfwOp, ok: string, body?: React.ReactNode, danger?: boolean) => setDlg({t: 'confirm', title, op, ok, body, danger})

  const policySel = (dir: 'incoming' | 'outgoing' | 'routed', label: string) => (
    <label className="pol">
      <span className="field-label">{label}</span>
      <select value={ufw.defaults[dir] || ''} onChange={e => confirm(`默认${label}策略改为「${POLICY[e.target.value]}」`,
        {op: 'default', direction: dir, policy: e.target.value}, '应用',
        <div className="dim">没有任何规则命中的{label}流量将被{POLICY[e.target.value]}。{dir === 'incoming' && e.target.value === 'allow' && <b> 入站默认允许相当于不设防，请确认。</b>}</div>)}>
        {!ufw.defaults[dir] && <option value="">未知</option>}
        {Object.entries(POLICY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
      </select>
    </label>
  )

  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <h2>ufw 状态</h2>
          <span className={'badge ' + (active ? 'good' : 'warn')}>{active ? '已启用' : ufw.status === 'inactive' ? '未启用' : '状态未知'}</span>
          <span className="sp"/>
          {active
            ? <button className="btn" onClick={() => confirm('停用 ufw', {op: 'disable'}, '停用',
                <div className="dim">停用后 ufw 的规则全部撤下，所有流量不再经过 ufw 过滤（规则本身保留，重新启用即恢复）。</div>, true)}>停用防火墙</button>
            : <button className="btn primary" onClick={() => confirm('启用 ufw', {op: 'enable'}, '启用',
                <div className="dim">启用后立即按下面的默认策略与规则过滤，并设为开机自启。
                  {ufw.defaults.incoming !== 'allow' && <> 默认入站为「{POLICY[ufw.defaults.incoming] || '?'}」：如果正通过 SSH 远程管理本机，请先确认规则里放行了 SSH 端口。</>}</div>)}>启用防火墙</button>}
        </div>
        <div className="pols">
          {policySel('incoming', '入站')}
          {policySel('outgoing', '出站')}
          {policySel('routed', '转发')}
          <label className="pol">
            <span className="field-label">日志级别</span>
            <select value={ufw.logging} onChange={e => confirm(`日志级别改为「${LOGGING[e.target.value]}」`, {op: 'logging', level: e.target.value}, '应用',
              <div className="dim">ufw 日志写入内核日志（journalctl -k 或 /var/log/ufw.log）。级别越高记录越多，「高」「全部」会产生大量日志。</div>)}>
              {Object.entries(LOGGING).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
        </div>
        {!active && <div className="hint" style={{marginTop: 8}}>未启用时也可以先配好规则，启用后一并生效。</div>}
      </div>

      {done && <div className="banner">
        <div style={{minWidth: 0}}>
          <b>{done.executed ? '已应用' : '已生成命令（未执行）'}</b>
          <pre className="raw cmd" style={{marginTop: 6, maxHeight: 160}}>{done.output.trim()}</pre>
        </div>
        <span className="sp"/>
        <button className="btn" onClick={() => setDone(null)}>知道了</button>
      </div>}

      <div className="card">
        <div className="card-head">
          <h2>规则</h2>
          <div className="seg">
            <button className={kind === 'all' ? 'on' : ''} onClick={() => setKind('all')}>全部 {groups.length}</button>
            {(['in', 'out', 'route'] as Kind[]).map(k => <button key={k} className={kind === k ? 'on' : ''} onClick={() => setKind(k)}>{KIND_LABEL[k]} {counts(k)}</button>)}
          </div>
          <input type="search" placeholder="搜索地址、端口、网卡、备注…" value={q} onChange={e => setQ(e.target.value)} style={{width: 220}}/>
          <span className="sp"/>
          <button className="btn primary" onClick={() => setDlg({t: 'edit'})}>＋ 添加规则</button>
        </div>
        {ufw.rulesError && <div className="form-err" style={{marginBottom: 8}}>读取规则失败：{ufw.rulesError}</div>}
        {shown.length ? <div className="tbl-wrap"><table className="ufw-tbl">
          <thead><tr>
            <th className="right">#</th><th>方向</th><th>动作</th><th>协议</th><th>源地址</th><th>源端口</th><th>目的地址</th><th>目的端口</th>
            <th>网卡</th><th>IP</th><th>备注</th><th className="right">操作</th>
          </tr></thead>
          <tbody>{shown.map(g => {
            const r = g.r
            const fams = [...new Set(g.rules.map(x => x.v6 ? 'v6' : 'v4'))].join('+')
            const app = !!(r.sapp || r.dapp)
            return (
              <tr key={g.key}>
                <td className="right num muted nowrap">{g.nums.join(', ')}</td>
                <td className="nowrap">{KIND_LABEL[kindOf(r)]}{r.log && <span className="tag" style={{marginLeft: 4}} title={r.log === 'log' ? '记录新连接' : '记录所有包'}>日志</span>}</td>
                <td><ActionBadge r={r}/></td>
                <td>{r.proto === 'any' ? <Any/> : r.proto.toUpperCase()}</td>
                <td>{val(r.src)}</td>
                <td>{r.sapp ? <span className="tag">{r.sapp}</span> : val(r.sport)}</td>
                <td>{val(r.dst)}</td>
                <td>{r.dapp ? <span className="tag">{r.dapp}</span> : val(r.dport)}</td>
                <td><IfaceCell r={r}/></td>
                <td><span className="tag">{fams === 'v4+v6' ? 'v4 + v6' : fams}</span></td>
                <td className="dim">{r.comment}</td>
                <td className="right nowrap">
                  <button className="link" disabled={app} title={app ? '应用配置（app）规则请用命令行修改' : ''} onClick={() => setDlg({t: 'edit', g})}>编辑</button>
                  <button className="link danger" style={{marginLeft: 10}} onClick={() => confirm(`删除规则 #${g.nums.join(', ')}`, {op: 'delete', old: r}, '删除',
                    <div><div className="dim">{summary(r)}{r.comment && <>（{r.comment}）</>}</div>
                      {g.rules.length > 1 && <div className="hint" style={{marginTop: 4}}>这条规则在 IPv4、IPv6 下各有一条，会一起删除。</div>}</div>, true)}>删除</button>
                </td>
              </tr>
            )
          })}</tbody>
        </table></div> : <div className="empty">{groups.length ? '没有符合筛选条件的规则' : '还没有任何规则：所有流量按默认策略处理'}</div>}
      </div>

      {dlg?.t === 'edit' && <RuleEditor old={dlg.g} groups={groups} ifaces={ifaces} onClose={close} onDone={finished}/>}
      {dlg?.t === 'confirm' && <ConfirmOp title={dlg.title} op={dlg.op} okText={dlg.ok} danger={dlg.danger} onClose={close} onDone={finished}>{dlg.body}</ConfirmOp>}
    </div>
  )
}
