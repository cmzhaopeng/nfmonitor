import {useEffect, useRef, useState} from 'react'
import {fmtRate} from './format'

export interface RatePoint { t: number; rx: number; tx: number }

const H = 200, PAD = {l: 64, r: 12, t: 10, b: 22}

/** 把上限取整到 1/2/5 × 1024^n，刻度好读。 */
function niceMax(v: number): number {
  if (v <= 0) return 1024
  const unit = Math.pow(1024, Math.floor(Math.log(v) / Math.log(1024)))
  for (const m of [1, 2, 5, 10, 20, 50, 100, 200, 500, 1024]) if (v <= m * unit) return m * unit
  return 1024 * unit
}

/** 上/下行速率折线图：同一个纵轴，十字线 + 悬浮提示。 */
export function RateChart({points, windowSec = 120}: {points: RatePoint[]; windowSec?: number}) {
  const box = useRef<HTMLDivElement>(null)
  const [w, setW] = useState(600)
  const [hover, setHover] = useState<number | null>(null)
  useEffect(() => {
    if (!box.current) return
    const ro = new ResizeObserver(es => setW(Math.max(280, es[0].contentRect.width)))
    ro.observe(box.current)
    return () => ro.disconnect()
  }, [])

  const now = points.length ? points[points.length - 1].t : Date.now()
  const t0 = now - windowSec * 1000
  const vis = points.filter(p => p.t >= t0)
  const max = niceMax(Math.max(1, ...vis.map(p => Math.max(p.rx, p.tx))))
  const iw = w - PAD.l - PAD.r, ih = H - PAD.t - PAD.b
  const x = (t: number) => PAD.l + ((t - t0) / (windowSec * 1000)) * iw
  const y = (v: number) => PAD.t + ih - (v / max) * ih
  const path = (k: 'rx' | 'tx') => vis.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p[k]).toFixed(1)}`).join('')
  const hp = hover != null ? vis[hover] : null

  const onMove = (e: React.MouseEvent) => {
    if (!vis.length || !box.current) return
    const mx = e.clientX - box.current.getBoundingClientRect().left
    let best = 0, bd = Infinity
    vis.forEach((p, i) => { const d = Math.abs(x(p.t) - mx); if (d < bd) { bd = d; best = i } })
    setHover(best)
  }

  return (
    <div className="chart" ref={box} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
      <svg height={H} role="img" aria-label="上下行速率">
        {[0, 0.25, 0.5, 0.75, 1].map(f => (
          <g key={f}>
            <line x1={PAD.l} x2={w - PAD.r} y1={y(max * f)} y2={y(max * f)} stroke={f === 0 ? 'var(--axis)' : 'var(--border)'} strokeWidth={1}/>
            <text x={PAD.l - 8} y={y(max * f) + 4} textAnchor="end" fontSize={11} fill="var(--muted)">{fmtRate(max * f)}</text>
          </g>
        ))}
        {[0, 0.25, 0.5, 0.75, 1].map(f => (
          <text key={f} x={PAD.l + iw * f} y={H - 5} fontSize={11} fill="var(--muted)" textAnchor={f === 0 ? 'start' : f === 1 ? 'end' : 'middle'}>
            {f === 1 ? '现在' : `-${Math.round(windowSec * (1 - f))}s`}
          </text>
        ))}
        <path d={path('rx')} fill="none" stroke="var(--rx)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round"/>
        <path d={path('tx')} fill="none" stroke="var(--tx)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round"/>
        {hp && <>
          <line x1={x(hp.t)} x2={x(hp.t)} y1={PAD.t} y2={PAD.t + ih} stroke="var(--axis)" strokeWidth={1}/>
          <circle cx={x(hp.t)} cy={y(hp.rx)} r={4} fill="var(--rx)" stroke="var(--surface)" strokeWidth={2}/>
          <circle cx={x(hp.t)} cy={y(hp.tx)} r={4} fill="var(--tx)" stroke="var(--surface)" strokeWidth={2}/>
        </>}
      </svg>
      {hp && (
        <div className="tip" style={x(hp.t) > w / 2 ? {right: w - x(hp.t) + 12, top: 14} : {left: x(hp.t) + 12, top: 14}}>
          <div className="muted">{new Date(hp.t).toLocaleTimeString()}</div>
          <div><span><i style={{background: 'var(--rx)'}}/>下行</span><b className="num">{fmtRate(hp.rx)}</b></div>
          <div><span><i style={{background: 'var(--tx)'}}/>上行</span><b className="num">{fmtRate(hp.tx)}</b></div>
        </div>
      )}
      {vis.length < 2 && <div className="empty" style={{position: 'absolute', inset: '40px 0 0 0'}}>正在采样…</div>}
    </div>
  )
}

/** 表格行内的小趋势线，只表达形状，数值由旁边的数字给出。 */
export function Spark({values, color}: {values: number[]; color: string}) {
  const W = 84, HH = 22
  const max = Math.max(1, ...values)
  const d = values.map((v, i) => `${i ? 'L' : 'M'}${((i / Math.max(1, values.length - 1)) * W).toFixed(1)},${(HH - 2 - (v / max) * (HH - 4)).toFixed(1)}`).join('')
  return <svg width={W} height={HH} aria-hidden="true"><path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round"/></svg>
}
