import {useCallback, useEffect, useRef, useState} from 'react'

export interface Addr { family: string; local: string; prefix: number; scope: string }
export interface Counters {
  rxBytes: number; txBytes: number; rxPackets: number; txPackets: number
  rxErrors: number; txErrors: number; rxDropped: number; txDropped: number
}
export interface Link {
  index: number; name: string; kind: string; class: 'physical' | 'tunnel' | 'virtual' | 'loopback'
  flags: string[]; state: string; up: boolean; mtu: number; mac: string; master: string
  speed: number; driver: string; addrs: Addr[]; stats: Counters
}
export interface StatSample { time: number; stats: Record<string, Counters> }
export interface Route {
  family: string; dst: string; gateway: string; dev: string; protocol: string; scope: string
  prefsrc: string; metric: number; type: string; flags: string[]
}
export interface Table { id: string; name: string; routes: Route[]; devs: string[] }
export interface Rule { family: string; priority: number; text: string; action: string; table: string; goto: number }
export interface Routing { rules: Rule[]; tables: Table[] }
export interface RouteGet { dst: string; gateway: string; dev: string; prefsrc: string; table: string; type: string; raw: string }
export interface Socket {
  proto: string; state: string; local: string; localPort: string; peer: string; peerPort: string
  iface: string; dev: string; process: string; app: string; pid: number; bytesSent: number; bytesRecv: number
}
export interface AppIface { dev: string; via: string; conns: number; rxRate: number; txRate: number; rxTotal: number; txTotal: number; udpRx: number; udpTx: number }
export interface AppProc { pid: number; user: string; cmdline: string; conns: number }
export interface App {
  name: string; procs: AppProc[]; conns: number; listens: number; udp: number
  rxRate: number; txRate: number; rxTotal: number; txTotal: number; udpRx: number; udpTx: number; ifaces: AppIface[]
}
export interface AppsSnapshot {
  since: number; time: number; apps: App[]
  udpMode: 'on' | 'need-priv' | 'error' | 'off'; udpError: string
}
export interface ProxySetting {
  source: string; key: string; value: string; host: string; port: string; process: string; pid: number; listen: boolean
}
export interface ProxyProcess { pid: number; name: string; kind: string; user: string; cmdline: string; listens: string[] }
export interface Tunnel {
  name: string; kind: string; up: boolean; addrs: string[]; mtu: number; tables: string[]
  routeCount: number; rules: Rule[]; default: boolean
}
export interface ProxyInfo {
  settings: ProxySetting[]; noProxy: string; gnomeMode: string; processes: ProxyProcess[]; tunnels: Tunnel[]
}
export interface FwRule {
  handle: number; text: string; hasCounter: boolean; packets: number; bytes: number
  verdict: string; target: string; comment: string
}
export interface FwChain {
  name: string; base: boolean; type: string; hook: string; device: string; priority: string; prio: number
  policy: string; owner: string; rules: FwRule[]
}
export interface FwObject { kind: string; name: string; raw: string }
export interface FwTable { family: string; name: string; backend: string; owner: string; chains: FwChain[]; objects: FwObject[] }
export interface UfwRule {
  num: number; v6: boolean; route: boolean; action: 'allow' | 'deny' | 'reject' | 'limit'; log: '' | 'log' | 'log-all'
  dir: 'in' | 'out'; ifaceIn: string; ifaceOut: string; proto: string
  src: string; sport: string; sapp: string; dst: string; dport: string; dapp: string; comment: string; spec: string[]
}
export interface UfwInfo {
  status: string; logging: string; defaults: Record<'incoming' | 'outgoing' | 'routed', string>
  ipv6: boolean; rules: UfwRule[]; rulesError?: string
}
export interface UfwOp {
  op: 'add' | 'delete' | 'replace' | 'move' | 'enable' | 'disable' | 'default' | 'logging'
  rule?: Partial<UfwRule>; position?: number; old?: UfwRule; before?: UfwRule; direction?: string; policy?: string; level?: string
}
/** 修改结果；warning 非空表示这次修改可能切断远程主机的 SSH 连接，执行时要带 confirm。 */
export interface UfwResult { commands: string[][]; output: string; executed: boolean; warning?: string }
export interface FirewalldZone {
  name: string; default: boolean; active: boolean; target: string
  interfaces: string[]; sources: string[]; services: string[]; ports: string[]; protocols: string[]
  masquerade: boolean; forwardPorts: string[]; sourcePorts: string[]; icmpBlocks: string[]; richRules: string[]
}
export interface FirewalldInfo { state: string; defaultZone: string; zones: FirewalldZone[]; services: string[]; error?: string }
export type FirewalldKind = 'service' | 'port' | 'source' | 'interface' | 'rich-rule' | 'masquerade'
export interface FirewalldOp { op: 'add' | 'remove' | 'default-zone'; zone: string; kind?: FirewalldKind; value?: string; confirm?: boolean }
export interface Firewall {
  privileged: boolean; tables: FwTable[]; raw: Record<string, string>; errors: Record<string, string>
  ufwStatus: string; ufw: UfwInfo | null; firewalld: FirewalldInfo | null; tools: Record<string, string>
}
export interface Meta {
  version: string; hostname: string; priv: 'root' | 'helper' | 'sudo' | 'none'
  remote: boolean; host?: string; name?: string; kernel?: string; rootErr?: string; error?: string
}

// ---- 当前查看的主机 ----
// 所有采集 / 修改接口都带上 ?host=<id>；空串 = 本机。界面切换主机时整棵组件树按 key 重建。
let currentHost = ''
export const setApiHost = (id: string) => { currentHost = id }
export const isRemote = () => currentHost !== ''
function withHost(url: string) {
  if (!currentHost || !url.startsWith('/api/') || url.startsWith('/api/hosts')) return url
  return url + (url.includes('?') ? '&' : '?') + 'host=' + encodeURIComponent(currentHost)
}

/** 接口返回 409 + lockout：这次修改可能切断远程主机的 SSH 连接，需要用户确认后带 confirm 重发。 */
export class LockoutError extends Error { lockout = true }

export async function getJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(withHost(url), init)
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    const msg = body?.error || `${url}: HTTP ${res.status}`
    throw body?.lockout ? new LockoutError(msg) : new Error(msg)
  }
  return body as T
}

export const elevate = () =>
  getJSON<{priv: string}>('/api/elevate', {method: 'POST', headers: {'X-Nfmonitor': '1'}})

const postJSON = <T,>(url: string, body: unknown) =>
  getJSON<T>(url, {method: 'POST', headers: {'X-Nfmonitor': '1', 'Content-Type': 'application/json'}, body: JSON.stringify(body)})
/** 只生成将要执行的 ufw 命令，不执行。 */
export const ufwPreview = (op: UfwOp) => postJSON<UfwResult>('/api/ufw/preview', op)
/** 真正执行（本机会弹系统授权框；远程主机经 SSH 以 root / sudo 执行）。 */
export const ufwApply = (op: UfwOp & {confirm?: boolean}) => postJSON<UfwResult>('/api/ufw/apply', op)
export const firewalldPreview = (op: FirewalldOp) => postJSON<UfwResult>('/api/firewalld/preview', op)
export const firewalldApply = (op: FirewalldOp) => postJSON<UfwResult>('/api/firewalld/apply', op)

// ---- 远程主机 ----
export type AuthKind = 'password' | 'key' | 'agent'
export interface HostConfig {
  id: string; name: string; addr: string; port: number; user: string; auth: AuthKind; keyPath?: string; hostKey?: string
}
export interface HostInfo { hostname: string; kernel: string; root: 'root' | 'sudo' | 'sudo-pw' | 'none'; rootErr?: string }
export interface HostView extends HostConfig {
  fingerprint: string; hasPassword: boolean; hasKeyPem: boolean; hasPassphrase: boolean; hasSudoPassword: boolean
  connected: boolean; error?: string; info: HostInfo
}
/** 机密：空串 = 不修改；clear 里列出的字段 = 清除。 */
export interface Secrets { password?: string; keyPem?: string; passphrase?: string; sudoPassword?: string; clear?: string[] }
export interface HostKeyProbe { hostKey: string; type: string; fingerprint: string; knownHosts: 'match' | 'mismatch' | 'unknown' }
export const listHosts = () => getJSON<{hosts: HostView[]; error?: string}>('/api/hosts')
export const probeHost = (addr: string, port: number) => postJSON<HostKeyProbe>('/api/hosts/probe', {addr, port})
export const testHost = (cfg: Partial<HostConfig>, secrets: Secrets) => postJSON<HostInfo>('/api/hosts/test', {...cfg, secrets})
export const saveHost = (cfg: Partial<HostConfig>, secrets: Secrets) => postJSON<HostView>('/api/hosts/save', {...cfg, secrets})
export const connectHost = (id: string) => postJSON<HostView>('/api/hosts/connect', {id})
export const disconnectHost = (id: string) => postJSON<HostView>('/api/hosts/disconnect', {id})
export const deleteHost = (id: string) => postJSON<{ok: boolean}>('/api/hosts/delete', {id})

export interface Polled<T> { data: T | null; error: string; loading: boolean; reload: () => void }

/** 取一次并按 intervalMs 轮询（0 = 不轮询）；窗口不可见时暂停。 */
export function usePoll<T>(url: string, intervalMs = 0): Polled<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const seq = useRef(0)
  const reload = useCallback(() => {
    const my = ++seq.current
    getJSON<T>(url)
      .then(d => { if (my === seq.current) { setData(d); setError('') } })
      .catch(e => { if (my === seq.current) setError(String(e.message || e)) })
      .finally(() => { if (my === seq.current) setLoading(false) })
  }, [url])
  useEffect(() => {
    setLoading(true)
    reload()
    if (!intervalMs) return
    const id = setInterval(() => { if (!document.hidden) reload() }, intervalMs)
    return () => clearInterval(id)
  }, [reload, intervalMs])
  return {data, error, loading, reload}
}
