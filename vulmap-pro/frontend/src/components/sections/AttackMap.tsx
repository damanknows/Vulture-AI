/**
 * AttackMap.tsx — Live threat intelligence visualization.
 * Left: canvas world map with animated bezier-curve attack arcs.
 * Right: simulated real-time threat feed panel with auto-updating events.
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Badge, PrimeCard } from '../ui'

// ── City nodes (normalized 0–1 coords, mapped to canvas at render) ───────────
const CITIES: [number, number][] = [
  [0.13, 0.28],  // New York
  [0.10, 0.22],  // Toronto
  [0.50, 0.18],  // London
  [0.52, 0.22],  // Paris
  [0.57, 0.20],  // Berlin
  [0.63, 0.24],  // Moscow
  [0.68, 0.35],  // Dubai
  [0.75, 0.32],  // Mumbai
  [0.82, 0.28],  // Singapore
  [0.87, 0.25],  // Tokyo
  [0.85, 0.42],  // Sydney
  [0.20, 0.55],  // São Paulo
  [0.48, 0.55],  // Nairobi
  [0.07, 0.35],  // Los Angeles
]

// Simplified continent outlines (normalized 0–1 coords)
const CONTINENTS: [number, number][][] = [
  // North America rough
  [[0.04,0.15],[0.22,0.12],[0.26,0.22],[0.22,0.32],[0.12,0.38],[0.06,0.35],[0.04,0.25]],
  // South America
  [[0.15,0.40],[0.24,0.40],[0.28,0.55],[0.22,0.72],[0.13,0.72],[0.10,0.58]],
  // Europe
  [[0.44,0.15],[0.60,0.13],[0.64,0.26],[0.56,0.30],[0.44,0.28]],
  // Africa
  [[0.44,0.30],[0.58,0.28],[0.60,0.50],[0.54,0.70],[0.44,0.68],[0.40,0.50]],
  // Asia
  [[0.60,0.14],[0.90,0.14],[0.92,0.35],[0.80,0.45],[0.68,0.40],[0.62,0.30]],
  // Australia
  [[0.78,0.50],[0.92,0.48],[0.92,0.62],[0.80,0.65],[0.75,0.58]],
]

interface Arc {
  from: number
  to:   number
  t:    number   // animation progress 0–1
  speed: number
  color: string
}

function lerpPoint(
  a: [number, number],
  b: [number, number],
  ctrl: [number, number],
  t: number,
): [number, number] {
  const x = (1-t)*(1-t)*a[0] + 2*(1-t)*t*ctrl[0] + t*t*b[0]
  const y = (1-t)*(1-t)*a[1] + 2*(1-t)*t*ctrl[1] + t*t*b[1]
  return [x, y]
}

function CanvasMap() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const arcsRef   = useRef<Arc[]>([])
  const rafRef    = useRef<number>(0)

  const initArcs = useCallback(() => {
    arcsRef.current = Array.from({ length: 8 }, (_, i) => {
      const from = Math.floor(Math.random() * CITIES.length)
      let to = Math.floor(Math.random() * CITIES.length)
      while (to === from) to = Math.floor(Math.random() * CITIES.length)
      return {
        from, to,
        t: Math.random(),
        speed: 0.002 + Math.random() * 0.003,
        color: i % 2 === 0 ? 'rgba(0,245,212,0.7)' : 'rgba(255,107,53,0.7)',
      }
    })
  }, [])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resize = () => {
      canvas.width  = canvas.offsetWidth
      canvas.height = canvas.offsetHeight
    }
    resize()
    window.addEventListener('resize', resize)
    initArcs()

    const W = () => canvas.width
    const H = () => canvas.height

    const toCanvas = ([nx, ny]: [number, number]): [number, number] =>
      [nx * W(), ny * H()]

    const draw = () => {
      ctx.clearRect(0, 0, W(), H())

      // Background
      ctx.fillStyle = '#0a0f1a'
      ctx.fillRect(0, 0, W(), H())

      // Continents
      CONTINENTS.forEach((poly) => {
        ctx.beginPath()
        poly.forEach(([nx, ny], i) => {
          const [x, y] = toCanvas([nx, ny])
          i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)
        })
        ctx.closePath()
        ctx.fillStyle   = 'rgba(31,41,55,0.9)'
        ctx.strokeStyle = 'rgba(55,65,81,0.5)'
        ctx.lineWidth   = 0.5
        ctx.fill()
        ctx.stroke()
      })

      // City dots
      CITIES.forEach(([nx, ny]) => {
        const [x, y] = toCanvas([nx, ny])
        ctx.beginPath()
        ctx.arc(x, y, 2.5, 0, Math.PI * 2)
        ctx.fillStyle = 'rgba(0,245,212,0.8)'
        ctx.fill()
        // Pulse ring
        ctx.beginPath()
        ctx.arc(x, y, 5, 0, Math.PI * 2)
        ctx.strokeStyle = 'rgba(0,245,212,0.2)'
        ctx.lineWidth   = 1
        ctx.stroke()
      })

      // Arcs
      arcsRef.current.forEach((arc) => {
        const a = CITIES[arc.from]
        const b = CITIES[arc.to]
        const [ax, ay] = toCanvas(a)
        const [bx, by] = toCanvas(b)

        // Control point: perpendicular up from midpoint
        const mx = (ax + bx) / 2
        const my = (ay + by) / 2 - Math.hypot(bx-ax, by-ay) * 0.4
        const ctrl: [number, number] = [mx / W(), my / H()]

        // Draw trail
        ctx.beginPath()
        for (let i = Math.max(0, arc.t - 0.25); i <= arc.t; i += 0.01) {
          const [px, py] = lerpPoint(a, b, ctrl, i)
          const [cx2, cy2] = toCanvas([px, py])
          i === Math.max(0, arc.t - 0.25) ? ctx.moveTo(cx2, cy2) : ctx.lineTo(cx2, cy2)
        }
        ctx.strokeStyle = arc.color.replace('0.7', '0.35')
        ctx.lineWidth   = 1.5
        ctx.stroke()

        // Draw tip dot
        const [tipX, tipY] = toCanvas(lerpPoint(a, b, ctrl, arc.t))
        ctx.beginPath()
        ctx.arc(tipX, tipY, 3, 0, Math.PI * 2)
        ctx.fillStyle = arc.color
        ctx.fill()

        // Advance
        arc.t += arc.speed
        if (arc.t > 1) {
          arc.t = 0
          const from = Math.floor(Math.random() * CITIES.length)
          let to = Math.floor(Math.random() * CITIES.length)
          while (to === from) to = Math.floor(Math.random() * CITIES.length)
          arc.from  = from
          arc.to    = to
          arc.color = Math.random() > 0.5 ? 'rgba(0,245,212,0.7)' : 'rgba(255,107,53,0.7)'
        }
      })

      rafRef.current = requestAnimationFrame(draw)
    }

    rafRef.current = requestAnimationFrame(draw)
    return () => {
      cancelAnimationFrame(rafRef.current)
      window.removeEventListener('resize', resize)
    }
  }, [initArcs])

  return (
    <div className="relative aspect-video rounded-xl overflow-hidden">
      <canvas ref={canvasRef} className="w-full h-full" />
      {/* LIVE badge overlay */}
      <div className="absolute bottom-4 left-4 flex items-center gap-2">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-acc opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-acc" />
        </span>
        <span className="text-xs font-mono text-acc">LIVE</span>
      </div>
    </div>
  )
}

// ── Threat feed ───────────────────────────────────────────────────────────────
type EventType = 'CRITICAL' | 'HIGH' | 'BLOCKED'
interface FeedEvent { id: number; time: string; type: EventType; message: string; target: string }

const SEED_EVENTS: FeedEvent[] = [
  { id:1, time:'13:41:02', type:'CRITICAL', message:'SQLi detected',      target:'api.acme.com:443'      },
  { id:2, time:'13:41:18', type:'BLOCKED',  message:'RCE attempt blocked', target:'10.0.0.4:22'           },
  { id:3, time:'13:41:34', type:'HIGH',     message:'XSS payload found',   target:'app.internal:3000'     },
  { id:4, time:'13:41:51', type:'CRITICAL', message:'Auth bypass attempt', target:'admin.corp.io:443'     },
  { id:5, time:'13:42:05', type:'BLOCKED',  message:'Port scan blocked',   target:'192.168.0.0/24'        },
  { id:6, time:'13:42:20', type:'HIGH',     message:'Brute force detected',target:'ssh.prod.io:22'        },
  { id:7, time:'13:42:37', type:'BLOCKED',  message:'Log4Shell blocked',   target:'legacy-svc.local:8080' },
  { id:8, time:'13:42:55', type:'CRITICAL', message:'0-day CVE-2024-9999', target:'db.cluster:5432'       },
]

const NEW_EVENTS: Omit<FeedEvent, 'id' | 'time'>[] = [
  { type:'CRITICAL', message:'SQL injection detected', target:'reports.svc:8080' },
  { type:'BLOCKED',  message:'CSRF attempt blocked',   target:'auth.internal:443' },
  { type:'HIGH',     message:'Exposed secrets found',  target:'git.corp.io:443' },
]

const EVENT_COLORS: Record<EventType, string> = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-acc-warm',
  BLOCKED:  'text-acc',
}

function ThreatFeed() {
  const [events, setEvents] = useState<FeedEvent[]>(SEED_EVENTS)
  const counterRef = useRef(SEED_EVENTS.length + 1)

  useEffect(() => {
    const timer = setInterval(() => {
      const template = NEW_EVENTS[Math.floor(Math.random() * NEW_EVENTS.length)]
      const now = new Date()
      const time = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`
      setEvents((prev) => [{ ...template, id: counterRef.current++, time }, ...prev.slice(0, 19)])
    }, 3000)
    return () => clearInterval(timer)
  }, [])

  return (
    <PrimeCard noPadding className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
        <span className="text-sm font-semibold text-white">Threat Feed</span>
        <Badge variant="red" dot>LIVE</Badge>
      </div>

      {/* Event list */}
      <div className="overflow-y-auto flex-1 divide-y divide-border max-h-64">
        {events.map((ev) => (
          <div key={ev.id} className="px-4 py-2.5 font-mono text-xs space-y-0.5 hover:bg-prime-700/30 transition-colors">
            <span className="text-text-muted">{ev.time}</span>
            <p className={EVENT_COLORS[ev.type]}>
              [{ev.type}] {ev.message}
            </p>
            <p className="text-text-secondary">{ev.target}</p>
          </div>
        ))}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-0 px-0 border-t border-border bg-prime-900/50 shrink-0">
        {[
          { value: '1,284', label: 'Blocked' },
          { value: '47',    label: 'Critical' },
          { value: '99ms',  label: 'Avg. TTD' },
        ].map(({ value, label }) => (
          <div key={label} className="text-center py-3 border-r border-border last:border-r-0">
            <p className="text-lg font-display font-bold text-acc">{value}</p>
            <p className="text-[10px] text-text-muted mt-0.5 font-mono uppercase tracking-wide">{label}</p>
          </div>
        ))}
      </div>
    </PrimeCard>
  )
}

// ── Section ───────────────────────────────────────────────────────────────────
export function AttackMap() {
  return (
    <section className="relative py-20 md:py-28 overflow-hidden">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: '-100px' }}
        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
        className="text-center max-w-2xl mx-auto px-6 md:px-12 mb-12"
      >
        <Badge variant="cyan">Live Threat Intelligence</Badge>
        <h2 className="mt-4 text-4xl md:text-5xl font-display font-bold tracking-tight text-white text-balance">
          Global Attack Surface
        </h2>
        <p className="mt-4 text-text-secondary">
          Real-time monitoring of attack vectors across your entire infrastructure, mapped globally as they happen.
        </p>
      </motion.div>

      {/* Content grid */}
      <div className="grid lg:grid-cols-[1fr_320px] gap-6 max-w-7xl mx-auto px-6 md:px-12">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
        >
          <CanvasMap />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 30 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.7, delay: 0.15, ease: [0.16, 1, 0.3, 1] }}
        >
          <ThreatFeed />
        </motion.div>
      </div>
    </section>
  )
}

export default AttackMap
