import {useEffect, useState} from 'react'
import {FirewalldInfo, FirewalldKind, FirewalldOp, FirewalldZone, firewalldApply, firewalldPreview, isRemote, LockoutError, UfwResult} from '../api'
import {Commands, LockoutWarning, Modal} from './Ufw'

const KIND_LABEL: Record<Exclude<FirewalldKind, 'masquerade'>, string> = {
  service: '服务', port: '端口', source: '来源地址', interface: '网卡', 'rich-rule': 'rich rule',
}
const KIND_HINT: Record<Exclude<FirewalldKind, 'masquerade'>, string> = {
  service: 'firewalld 预定义的服务名，例如 ssh、http、https',
  port: '端口/协议，例如 8080/tcp、60000-61000/udp',
  source: '来自这些地址的连接归入本区域：IP、网段（10.0.0.0/8）、MAC 或 ipset:名称',
  interface: '从这块网卡进来的连接归入本区域（会从原区域移走）',
  'rich-rule': '完整的 rich rule，例如 rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept',
}
const errText = (e: any) => String(e?.message || e)

/** 预览 + 确认 + 执行一次 firewalld 修改。 */
function FwdConfirm({title, op, onClose, onDone, danger}: {title: string; op: FirewalldOp; onClose: () => void; onDone: (r: UfwResult) => void; danger?: boolean}) {
  const [cmds, setCmds] = useState<string[][]>([])
  const [err, setErr] = useState('')
  const [warning, setWarning] = useState('')
  const [ack, setAck] = useState(false)
  const [busy, setBusy] = useState(false)
  const [runErr, setRunErr] = useState('')
  const key = JSON.stringify(op)
  useEffect(() => {
    let live = true
    firewalldPreview(op).then(r => { if (live) { setCmds(r.commands); setWarning(r.warning || ''); setErr('') } })
      .catch(e => { if (live) { setCmds([]); setErr(errText(e)) } })
    return () => { live = false }
  }, [key])
  const run = async () => {
    setBusy(true); setRunErr('')
    try { onDone(await firewalldApply({...op, confirm: ack || undefined})) } catch (e) {
      setRunErr(e instanceof LockoutError ? '执行前的检查发现这次修改可能切断 SSH 连接，已取消：' + e.message : errText(e))
    }
    setBusy(false)
  }
  return (
    <Modal title={title} onClose={onClose} foot={<>
      {runErr && <div className="form-err" style={{flex: 1}}>{runErr}</div>}
      <span className="sp"/>
      <button className="btn" onClick={onClose}>取消</button>
      <button className={'btn ' + (danger || warning ? 'danger' : 'primary')} disabled={busy || !!err || !cmds.length || (!!warning && !ack)} onClick={run}>
        {busy ? (isRemote() ? '执行中…' : '等待系统授权…') : '执行'}</button>
    </>}>
      <div className="hint">同时修改运行时配置和永久配置（--permanent），重启 firewalld 后依然生效。</div>
      <div className="field-label" style={{marginTop: 10}}>将执行</div>
      <Commands cmds={cmds} err={err}/>
      <LockoutWarning warning={warning} ack={ack} setAck={setAck}/>
    </Modal>
  )
}

function Items({zone, kind, items, onRemove}: {zone: string; kind: FirewalldKind; items: string[]; onRemove: (op: FirewalldOp, title: string) => void}) {
  if (!items.length) return <span className="muted">无</span>
  return <div className="zone-items">{items.map(v => (
    <span className="zone-item" key={v}>{v}
      <button title="移除" aria-label={`移除 ${v}`} onClick={() => onRemove({op: 'remove', zone, kind, value: v}, `从区域 ${zone} 移除${KIND_LABEL[kind as keyof typeof KIND_LABEL]} ${v}`)}>✕</button>
    </span>
  ))}</div>
}

function ZoneCard({z, info, onOp}: {z: FirewalldZone; info: FirewalldInfo; onOp: (op: FirewalldOp, title: string, danger?: boolean) => void}) {
  const [kind, setKind] = useState<Exclude<FirewalldKind, 'masquerade'>>('service')
  const [value, setValue] = useState('')
  const remove = (op: FirewalldOp, title: string) => onOp(op, title, true)
  return (
    <div className="card">
      <div className="card-head">
        <h2><code style={{fontSize: 14}}>{z.name}</code></h2>
        {z.default && <span className="badge info">默认区域</span>}
        <span className={'badge ' + (z.active ? 'good' : 'plain')}>{z.active ? '生效中' : '未绑定网卡 / 来源'}</span>
        <span className="tag">target {z.target || 'default'}</span>
        <span className="sp"/>
        {!z.default && <button className="btn" onClick={() => onOp({op: 'default-zone', zone: z.name}, `把 ${z.name} 设为默认区域`, true)}>设为默认</button>}
        <button className="btn" onClick={() => onOp({op: z.masquerade ? 'remove' : 'add', zone: z.name, kind: 'masquerade'}, `${z.masquerade ? '关闭' : '开启'}区域 ${z.name} 的地址伪装`)}>
          {z.masquerade ? '关闭地址伪装' : '开启地址伪装'}</button>
      </div>
      <div className="zone-grid">
        <span className="field-label">网卡</span><Items zone={z.name} kind="interface" items={z.interfaces} onRemove={remove}/>
        <span className="field-label">来源</span><Items zone={z.name} kind="source" items={z.sources} onRemove={remove}/>
        <span className="field-label">服务</span><Items zone={z.name} kind="service" items={z.services} onRemove={remove}/>
        <span className="field-label">端口</span><Items zone={z.name} kind="port" items={z.ports} onRemove={remove}/>
        <span className="field-label">rich rules</span><Items zone={z.name} kind="rich-rule" items={z.richRules} onRemove={remove}/>
        {z.forwardPorts.length > 0 && <><span className="field-label">端口转发</span><span className="fp">{z.forwardPorts.join('  ')}</span></>}
        {z.protocols.length > 0 && <><span className="field-label">协议</span><span className="fp">{z.protocols.join(' ')}</span></>}
        {z.icmpBlocks.length > 0 && <><span className="field-label">ICMP 屏蔽</span><span className="fp">{z.icmpBlocks.join(' ')}</span></>}
      </div>
      <form className="card-head" style={{marginTop: 12, marginBottom: 0}} onSubmit={e => {
        e.preventDefault()
        if (value.trim()) onOp({op: 'add', zone: z.name, kind, value: value.trim()}, `向区域 ${z.name} 添加${KIND_LABEL[kind]} ${value.trim()}`)
      }}>
        <select value={kind} onChange={e => { setKind(e.target.value as any); setValue('') }} aria-label="添加类型">
          {Object.entries(KIND_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        <input type="text" list={kind === 'service' ? `fwd-svc-${z.name}` : undefined} value={value} onChange={e => setValue(e.target.value)}
               placeholder={KIND_HINT[kind]} style={{flex: 1, minWidth: 220}} aria-label="值"/>
        {kind === 'service' && <datalist id={`fwd-svc-${z.name}`}>{info.services.filter(s => !z.services.includes(s)).map(s => <option key={s} value={s}/>)}</datalist>}
        <button className="btn primary" type="submit" disabled={!value.trim()}>添加…</button>
      </form>
    </div>
  )
}

export default function FirewalldPanel({info, onChanged}: {info: FirewalldInfo; onChanged: () => void}) {
  const [dlg, setDlg] = useState<{op: FirewalldOp; title: string; danger?: boolean} | null>(null)
  const [done, setDone] = useState<UfwResult | null>(null)
  const [showAll, setShowAll] = useState(false)
  if (info.error) return <div className="banner err">读取 firewalld 失败：{info.error}</div>
  if (info.state !== 'running') return <div className="card empty">firewalld 已安装但没有运行（状态：{info.state || '未知'}）。</div>
  const zones = showAll ? info.zones : info.zones.filter(z => z.active || z.default)
  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <h2>firewalld</h2><span className="badge good">运行中</span>
          <span className="muted">默认区域 <code>{info.defaultZone}</code> · {info.zones.length} 个区域</span>
          <span className="sp"/>
          <label className="check"><input type="checkbox" checked={showAll} onChange={e => setShowAll(e.target.checked)}/>显示未生效的区域</label>
        </div>
        <div className="hint">连接先按来源地址、再按入口网卡匹配区域，都不匹配时进默认区域；区域里列出的服务、端口被放行，其余按 target 处理（default 即拒绝）。</div>
      </div>
      {done && <div className="banner">
        <div><b>已执行</b>{done.output && <pre className="raw cmd" style={{marginTop: 6}}>{done.output.trim()}</pre>}</div>
        <span className="sp"/><button className="btn ghost" onClick={() => setDone(null)}>✕</button>
      </div>}
      {zones.map(z => <ZoneCard key={z.name} z={z} info={info} onOp={(op, title, danger) => setDlg({op, title, danger})}/>)}
      {dlg && <FwdConfirm title={dlg.title} op={dlg.op} danger={dlg.danger} onClose={() => setDlg(null)} onDone={r => { setDlg(null); setDone(r); onChanged() }}/>}
    </div>
  )
}
