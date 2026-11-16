import {createContext, useContext, useEffect, useRef, useState} from 'react'
import {getJSON, StatSample} from './api'
import {RatePoint} from './RateChart'

const KEEP = 300 // 保留最近 5 分钟（每秒一个点）

export interface Rates { history: Record<string, RatePoint[]>; error: string }
const Ctx = createContext<Rates>({history: {}, error: ''})
export const useRates = () => useContext(Ctx)

/** 每秒采一次 /api/stats，把相邻两次计数器之差换算成各网卡的速率。 */
export function RatesProvider({children}: {children: React.ReactNode}) {
  const [rates, setRates] = useState<Rates>({history: {}, error: ''})
  const prev = useRef<StatSample | null>(null)
  const hist = useRef<Record<string, RatePoint[]>>({})
  useEffect(() => {
    let stop = false
    const tick = async () => {
      if (document.hidden) return
      try {
        const s = await getJSON<StatSample>('/api/stats')
        if (stop) return
        const p = prev.current
        prev.current = s
        if (!p || s.time <= p.time) return
        // 窗口被挂起很久后的第一个样本只是长期平均，会在图上画出假的平台，直接丢掉。
        if (s.time - p.time > 5000) { hist.current = {}; return }
        const dt = (s.time - p.time) / 1000
        const next: Record<string, RatePoint[]> = {}
        for (const [name, c] of Object.entries(s.stats)) {
          const o = p.stats[name]
          if (!o) continue
          // 计数器回绕或网卡重建时差值为负，按 0 处理。
          const pt = {t: s.time, rx: Math.max(0, c.rxBytes - o.rxBytes) / dt, tx: Math.max(0, c.txBytes - o.txBytes) / dt}
          next[name] = [...(hist.current[name] || []).slice(-(KEEP - 1)), pt]
        }
        hist.current = next
        setRates({history: next, error: ''})
      } catch (e: any) {
        if (!stop) setRates(r => ({...r, error: String(e.message || e)}))
      }
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => { stop = true; clearInterval(id) }
  }, [])
  return <Ctx.Provider value={rates}>{children}</Ctx.Provider>
}

export const lastRate = (h: RatePoint[] | undefined) => h && h.length ? h[h.length - 1] : {t: 0, rx: 0, tx: 0}
