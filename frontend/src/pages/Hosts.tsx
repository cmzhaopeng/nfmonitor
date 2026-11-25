import {useState} from 'react'
import {
  AuthKind, canWrite, connectHost, hasLocal, isServer, deleteHost, disconnectHost, HostConfig, HostInfo, HostKeyProbe, HostView, probeHost, saveHost, Secrets, testHost, usePoll,
} from '../api'
import {ErrorBanner} from '../App'
import {Modal} from './Ufw'

const AUTH_LABEL: Record<AuthKind, string> = {password: '口令', key: '私钥', agent: 'ssh-agent'}
const ROOT_LABEL: Record<string, string> = {root: 'root 登录', sudo: 'sudo（免密）', 'sudo-pw': 'sudo（口令）', none: '无 root'}
const errText = (e: any) => String(e?.message || e)

function RootBadge({info}: {info: HostInfo}) {
  if (!info?.root) return null
  return <span className={'badge ' + (info.root === 'none' ? 'warn' : 'good')} title={info.rootErr || ''}>{ROOT_LABEL[info.root] || info.root}</span>
}

interface Draft {
  id: string; name: string; addr: string; port: string; user: string; auth: AuthKind; keyPath: string
  password: string; keyPem: string; passphrase: string; sudoPassword: string; clear: string[]
}

function HostEditor({old, onClose, onSaved}: {old?: HostView; onClose: () => void; onSaved: () => void}) {
  const [d, setD] = useState<Draft>({
    id: old?.id || '', name: old?.name || '', addr: old?.addr || '', port: String(old?.port || 22), user: old?.user || 'root',
    auth: old?.auth || 'password', keyPath: old?.keyPath || '', password: '', keyPem: '', passphrase: '', sudoPassword: '', clear: [],
  })
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD(x => ({...x, [k]: v}))
  // 主机公钥：编辑时沿用已信任的；地址或端口变了必须重新确认。
  const [probe, setProbe] = useState<HostKeyProbe | null>(null)
  const [trusted, setTrusted] = useState(false)
  const addrChanged = !old || old.addr !== d.addr.trim() || String(old.port) !== d.port.trim()
  const hostKey = probe && trusted ? probe.hostKey : !addrChanged ? old?.hostKey || '' : ''
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  const [tested, setTested] = useState<HostInfo | null>(null)

  const cfg = (): Partial<HostConfig> => ({
    id: d.id || undefined, name: d.name, addr: d.addr.trim(), port: Number(d.port) || 22, user: d.user.trim(), auth: d.auth,
    keyPath: d.auth === 'key' && !isServer() ? d.keyPath.trim() : '', hostKey,
  })
  const secrets = (): Secrets => {
    const s: Secrets = {clear: [...d.clear]}
    if (d.auth === 'password' && d.password) s.password = d.password
    if (d.auth === 'key' && d.keyPem.trim()) s.keyPem = d.keyPem.trim() + '\n'
    if (d.auth === 'key' && d.passphrase) s.passphrase = d.passphrase
    if (d.sudoPassword) s.sudoPassword = d.sudoPassword
    // 换了认证方式：清掉用不上的旧机密，不留在配置文件里。
    if (d.auth !== 'password') s.clear!.push('password')
    if (d.auth !== 'key') s.clear!.push('keyPem', 'passphrase')
    return s
  }
  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what); setErr('')
    try { await fn() } catch (e) { setErr(errText(e)) }
    setBusy('')
  }
  const doProbe = () => run('probe', async () => {
    setTrusted(false); setTested(null)
    const p = await probeHost(d.addr.trim(), Number(d.port) || 22)
    setProbe(p)
    if (p.knownHosts === 'match') setTrusted(true)
  })
  const doTest = () => run('test', async () => { setTested(await testHost(cfg(), secrets())) })
  const doSave = () => run('save', async () => { await saveHost(cfg(), secrets()); onSaved() })
  const toggleClear = (f: string, on: boolean) => set('clear', on ? [...d.clear, f] : d.clear.filter(x => x !== f))
  const saved = (has: boolean | undefined, f: string) => has && !d.clear.includes(f) ? '已保存，留空表示不修改' : ''

  return (
    <Modal wide title={old ? `编辑主机 ${old.name}` : '添加远程主机'} onClose={onClose} foot={<>
      {err && <div className="form-err" style={{flex: 1}}>{err}</div>}
      <span className="sp"/>
      <button className="btn" onClick={onClose}>取消</button>
      <button className="btn" disabled={!!busy || !hostKey} onClick={doTest}>{busy === 'test' ? '连接中…' : '测试连接'}</button>
      <button className="btn primary" disabled={!!busy || !hostKey} onClick={doSave}>{busy === 'save' ? '保存中…' : '保存'}</button>
    </>}>
      <div className="form">
        <label className="field"><span className="field-label">主机地址（IP 或域名）</span>
          <input type="text" value={d.addr} placeholder="192.168.1.20" onChange={e => set('addr', e.target.value)}/></label>
        <label className="field"><span className="field-label">SSH 端口</span>
          <input type="number" min={1} max={65535} value={d.port} onChange={e => set('port', e.target.value)}/></label>
        <label className="field"><span className="field-label">用户</span>
          <input type="text" value={d.user} onChange={e => set('user', e.target.value)}/></label>
        <label className="field"><span className="field-label">显示名称</span>
          <input type="text" maxLength={64} placeholder={`${d.user || '用户'}@${d.addr || '地址'}`} value={d.name} onChange={e => set('name', e.target.value)}/></label>

        <div className="form-sec">认证方式</div>
        <div className="field span2">
          <div className="seg">{(Object.keys(AUTH_LABEL) as AuthKind[]).filter(k => !isServer() || k !== 'agent').map(k =>
            <button key={k} className={d.auth === k ? 'on' : ''} onClick={() => set('auth', k)}>{AUTH_LABEL[k]}</button>)}</div>
        </div>
        {d.auth === 'password' && <label className="field span2"><span className="field-label">登录口令</span>
          <input type="password" autoComplete="new-password" placeholder={saved(old?.hasPassword, 'password')} value={d.password} onChange={e => set('password', e.target.value)}/></label>}
        {d.auth === 'key' && <>
          {!isServer() && <label className="field span2"><span className="field-label">私钥文件路径（本机）</span>
            <input type="text" placeholder="~/.ssh/id_ed25519" value={d.keyPath} onChange={e => set('keyPath', e.target.value)}/>
            <span className="hint">程序每次连接时读取这个文件，配置里只记路径。也可以不填路径，直接在下面粘贴私钥内容。</span></label>}
          <label className="field span2"><span className="field-label">{isServer() ? '私钥内容' : '或粘贴私钥内容'}</span>
            <textarea spellCheck={false} placeholder={saved(old?.hasKeyPem, 'keyPem') || '-----BEGIN OPENSSH PRIVATE KEY-----'} value={d.keyPem} onChange={e => set('keyPem', e.target.value)}/>
            {old?.hasKeyPem && <label className="check"><input type="checkbox" checked={d.clear.includes('keyPem')} onChange={e => toggleClear('keyPem', e.target.checked)}/>删除已保存的私钥内容（改用文件路径）</label>}</label>
          <label className="field span2"><span className="field-label">私钥口令（私钥有口令保护时填写）</span>
            <input type="password" autoComplete="new-password" placeholder={saved(old?.hasPassphrase, 'passphrase')} value={d.passphrase} onChange={e => set('passphrase', e.target.value)}/></label>
        </>}
        {d.auth === 'agent' && <div className="field span2 hint">使用本机 ssh-agent 里已加载的密钥（需要启动 nfmonitor 时设置了 SSH_AUTH_SOCK）。</div>}

        <div className="form-sec">root 权限（读取防火墙规则、修改防火墙需要）</div>
        <label className="field span2"><span className="field-label">sudo 口令（可选）</span>
          <input type="password" autoComplete="new-password" placeholder={saved(old?.hasSudoPassword, 'sudoPassword') || (d.auth === 'password' ? '留空则用登录口令；免密 sudo 或 root 登录不用填' : '免密 sudo 或 root 登录不用填')}
                 value={d.sudoPassword} onChange={e => set('sudoPassword', e.target.value)}/>
          {old?.hasSudoPassword && <label className="check"><input type="checkbox" checked={d.clear.includes('sudoPassword')} onChange={e => toggleClear('sudoPassword', e.target.checked)}/>删除已保存的 sudo 口令</label>}</label>

        <div className="form-sec">主机指纹</div>
        <div className="field span2">
          {!addrChanged && old?.fingerprint && !probe && <div>已信任：<span className="fp">{old.fingerprint}</span></div>}
          {probe && <>
            <div><span className="tag">{probe.type}</span> <span className="fp">{probe.fingerprint}</span></div>
            {probe.knownHosts === 'match' && <div className="hint">与本机 ~/.ssh/known_hosts 里记录的一致。</div>}
            {probe.knownHosts === 'mismatch' && <div className="form-err">与本机 ~/.ssh/known_hosts 里记录的不一致！可能遭遇中间人攻击，除非确认主机重装过，否则不要信任。</div>}
            {probe.knownHosts === 'unknown' && <div className="hint">本机 known_hosts 里没有这台主机。请在主机上运行 <code>for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done</code> 核对。</div>}
            <label className="check" style={{marginTop: 4}}><input type="checkbox" checked={trusted} onChange={e => setTrusted(e.target.checked)}/>我已核对，信任这台主机的密钥</label>
          </>}
          <div style={{marginTop: 6}}>
            <button className="btn" disabled={!!busy || !d.addr.trim()} onClick={doProbe}>{busy === 'probe' ? '获取中…' : probe || (!addrChanged && old?.fingerprint) ? '重新获取指纹' : '获取主机指纹'}</button>
            {!hostKey && <span className="hint" style={{marginLeft: 8}}>首次连接要先确认主机指纹，防止连到冒充的主机。</span>}
          </div>
        </div>
      </div>
      {tested && <div className="banner" style={{marginTop: 12}}>
        <div><b>连接成功：{tested.hostname}</b> <span className="dim">{tested.kernel}</span> <RootBadge info={tested}/>
          {tested.rootErr && <div className="dim">{tested.rootErr}</div>}</div>
      </div>}
      <div className="hint" style={{marginTop: 10}}>{isServer()
        ? '口令、私钥内容和 sudo 口令加密保存在服务器数据目录的 hosts.json，加密密钥由管理员单独保管（不在数据目录里）。'
        : '口令、私钥内容和 sudo 口令加密保存在 ~/.config/nfmonitor/hosts.json（仅本用户可读），密钥在同目录的 secret.key。'}</div>
    </Modal>
  )
}

export default function HostsPage({current, onUse, onLeave, onChanged}: {
  current: string; onUse: (id: string) => void; onLeave: () => void; onChanged: () => void
}) {
  const {data, error, reload} = usePoll<{hosts: HostView[]; error?: string}>('/api/hosts', 5000)
  const [edit, setEdit] = useState<HostView | 'new' | null>(null)
  const [del, setDel] = useState<HostView | null>(null)
  const [busy, setBusy] = useState('')
  const [rowErr, setRowErr] = useState<Record<string, string>>({})
  const changed = () => { reload(); onChanged() }
  const connect = async (h: HostView) => {
    setBusy(h.id); setRowErr(r => ({...r, [h.id]: ''}))
    try { await connectHost(h.id) } catch (e) { setRowErr(r => ({...r, [h.id]: errText(e)})) }
    setBusy(''); reload()
  }
  // 断开正在查看的主机：回到本机（停留在本页）。
  const disconnect = async (h: HostView) => {
    setBusy(h.id); setRowErr(r => ({...r, [h.id]: ''}))
    try { await disconnectHost(h.id); if (current === h.id) onLeave() } catch (e) { setRowErr(r => ({...r, [h.id]: errText(e)})) }
    setBusy(''); reload()
  }
  const hosts = data?.hosts || []
  return (
    <div className="page">
      <div className="page-head">
        <div><h1>主机管理</h1><p>配置要监控的远程主机：通过 SSH 采集网卡、路由、连接、防火墙等信息，并可在「防火墙」页修改 ufw / firewalld</p></div>
        <span className="sp"/>
        {canWrite() && <button className="btn primary" disabled={!!data?.error} onClick={() => setEdit('new')}>添加主机</button>}
      </div>
      <ErrorBanner error={error || data?.error || ''}/>
      <div className="card">
        {hosts.length ? <div className="tbl-wrap"><table className="host-list">
          <thead><tr><th>名称</th><th>地址</th><th>用户 / 认证</th><th>状态</th><th>指纹</th><th/></tr></thead>
          <tbody>
          {hasLocal() && <tr className={current === '' ? 'sel' : ''}>
            <td><b>本机</b></td><td className="muted">—</td><td className="muted">—</td><td><span className="badge good">本地</span></td><td/>
            <td className="right nowrap">{current !== '' && <button className="btn" onClick={() => onUse('')}>查看</button>}</td>
          </tr>}
          {hosts.map(h => (
            <tr key={h.id} className={current === h.id ? 'sel' : ''}>
              <td><b>{h.name}</b></td>
              <td className="mono">{h.addr}:{h.port}</td>
              <td>{h.user} · {AUTH_LABEL[h.auth]}</td>
              <td>
                {h.connected ? <><span className="badge good">已连接</span> <RootBadge info={h.info}/></>
                  : h.error ? <span className="badge crit" title={h.error}>连接失败</span> : <span className="badge plain">未连接</span>}
                {(rowErr[h.id] || (!h.connected && h.error)) && <div className="form-err" style={{maxWidth: 360}}>{rowErr[h.id] || h.error}</div>}
              </td>
              <td className="fp">{h.fingerprint || <span className="form-err">未确认</span>}</td>
              <td className="right nowrap">
                {current !== h.id && <button className="btn primary" onClick={() => onUse(h.id)}>查看</button>}{' '}
                <button className="btn" disabled={busy === h.id} onClick={() => connect(h)}>{busy === h.id ? '处理中…' : h.connected ? '重连' : '连接'}</button>{' '}
                {canWrite() && <>
                  {h.connected && <><button className="btn" disabled={busy === h.id} onClick={() => disconnect(h)}>断开</button>{' '}</>}
                  <button className="btn" onClick={() => setEdit(h)}>编辑</button>{' '}
                  <button className="link danger" onClick={() => setDel(h)}>删除</button>
                </>}
              </td>
            </tr>
          ))}
          </tbody>
        </table></div> : <div className="empty">{canWrite() ? '还没有远程主机。点右上角「添加主机」，填写 IP、端口、用户和认证方式。' : '还没有纳管主机，请联系管理员添加。'}</div>}
      </div>
      <div className="card dim">
        <b>说明</b>
        <ul style={{margin: '6px 0 0', paddingLeft: 18}}>
          <li>远程主机上需要有 <code>ip</code>、<code>ss</code>、<code>ps</code>（iproute2、procps），读取防火墙需要 root：用 root 登录，或给登录用户配置 sudo。</li>
          {isServer()
            ? <li>服务启动后按需连接：打开「所有主机」或选中主机时才连接。点「断开」后不会自动重连，「所有主机」也会跳过它。</li>
            : <li>程序启动时只看本机，不会自动连接远程主机；选中或点「查看」「连接」时才连接。点「断开」后不会自动重连。</li>}
          {isServer() && <li>服务器版只支持口令和粘贴的私钥（不读服务器上的私钥文件，也不用 ssh-agent）。新增、修改、删除主机和修改防火墙前要再次输入登录口令，所有操作记入审计日志。</li>}
          <li>修改远程防火墙前会检查当前 SSH 连接是否会被切断；有风险时要求再次确认。</li>
          <li>远程主机暂不统计 UDP 流量（需要 bpftrace 探针），也不读取桌面环境的代理设置。</li>
        </ul>
      </div>
      {edit && <HostEditor old={edit === 'new' ? undefined : edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); changed() }}/>}
      {del && <Modal title={`删除主机 ${del.name}`} onClose={() => setDel(null)} foot={<>
        <span className="sp"/>
        <button className="btn" onClick={() => setDel(null)}>取消</button>
        <button className="btn danger" onClick={async () => {
          try { await deleteHost(del.id); setDel(null); if (current === del.id) onUse(''); changed() } catch (e) { setRowErr(r => ({...r, [del.id]: errText(e)})); setDel(null) }
        }}>删除</button>
      </>}>
        会断开连接，并从配置文件里删除这台主机及其保存的口令 / 私钥。远程主机本身不受影响。
      </Modal>}
    </div>
  )
}
