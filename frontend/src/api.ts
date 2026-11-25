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
  op: 'add' | 'delete' | 'replace' | 'enable' | 'disable' | 'default' | 'logging'
  rule?: Partial<UfwRule>; position?: number; old?: UfwRule; direction?: string; policy?: string; level?: string
}
export interface UfwResult { commands: string[][]; output: string; executed: boolean }
export interface Firewall {
  privileged: boolean; tables: FwTable[]; raw: Record<string, string>; errors: Record<string, string>
  ufwStatus: string; ufw: UfwInfo | null; tools: Record<string, string>
}
export interface Meta { version: string; hostname: string; priv: 'root' | 'helper' | 'none' }

export async function getJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  const body = await res.json().catch(() => null)
  if (!res.ok) throw new Error(body?.error || `${url}: HTTP ${res.status}`)
  return body as T
}

export const elevate = () =>
  getJSON<{priv: string}>('/api/elevate', {method: 'POST', headers: {'X-Nfmonitor': '1'}})

const postJSON = <T,>(url: string, body: unknown) =>
  getJSON<T>(url, {method: 'POST', headers: {'X-Nfmonitor': '1', 'Content-Type': 'application/json'}, body: JSON.stringify(body)})
/** 只生成将要执行的 ufw 命令，不执行。 */
export const ufwPreview = (op: UfwOp) => postJSON<UfwResult>('/api/ufw/preview', op)
/** 真正执行（会弹系统授权框）。 */
export const ufwApply = (op: UfwOp) => postJSON<UfwResult>('/api/ufw/apply', op)

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
