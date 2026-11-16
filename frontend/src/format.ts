const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

export function fmtBytes(n: number, digits = 1): string {
  if (!isFinite(n) || n <= 0) return '0 B'
  let i = 0
  while (n >= 1024 && i < UNITS.length - 1) { n /= 1024; i++ }
  return `${i === 0 ? Math.round(n) : n.toFixed(n >= 100 ? 0 : digits)} ${UNITS[i]}`
}
export const fmtRate = (n: number) => fmtBytes(n) + '/s'

export function fmtCount(n: number): string {
  if (n < 1e4) return String(n)
  if (n < 1e6) return (n / 1e3).toFixed(1) + 'k'
  if (n < 1e9) return (n / 1e6).toFixed(1) + 'M'
  return (n / 1e9).toFixed(1) + 'G'
}

export const KIND_LABEL: Record<string, string> = {
  ethernet: '有线网卡', wifi: '无线网卡', loopback: '回环', tun: 'TUN', tap: 'TAP', wireguard: 'WireGuard',
  bridge: '网桥', veth: 'veth', vlan: 'VLAN', bond: 'bond', dummy: 'dummy', vxlan: 'VXLAN', tunnel: '隧道', virtual: '虚拟',
}
export const CLASS_LABEL: Record<string, string> = {physical: '物理', tunnel: '隧道', virtual: '虚拟', loopback: '回环'}
