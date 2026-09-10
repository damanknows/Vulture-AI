/**
 * Hero.tsx — PrimeSec landing page hero section.
 * 2-column layout: content left, animated product portal mockup right.
 * Framer Motion stagger entry for the left column.
 * Right card floats on `animate-float` CSS keyframe.
 */

import { type Variants, motion } from 'framer-motion'
import { Play } from 'lucide-react'
import { Badge, PrimeButton, PrimeCard, GridBackground, MetricStat } from '../ui'

// ── Framer Motion variants ──────────────────────────────────────────────────
const EXPO = [0.16, 1, 0.3, 1] as [number, number, number, number]

const container: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.1 } },
}

const item: Variants = {
  hidden: { opacity: 0, y: 20 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.6, ease: EXPO } },
}

// ── Product portal mockup (right column) ────────────────────────────────────
function PortalMockup() {
  return (
    <PrimeCard variant="accent" noPadding className="overflow-hidden">
      {/* Window chrome */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-prime-900/50">
        <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
        <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
        <span className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
        <span className="ml-3 font-mono text-xs text-text-muted">vulture.dashboard — live</span>
        <span className="ml-auto flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-acc animate-pulse" />
          <span className="font-mono text-[10px] text-acc">SCANNING</span>
        </span>
      </div>

      {/* Dashboard body */}
      <div className="p-4 space-y-3 bg-prime-900/30">
        {/* Fake scan log */}
        <div className="bg-prime-900 rounded-lg p-3 font-mono text-xs leading-relaxed border border-border">
          <p><span className="text-text-muted">[13:41:07] </span><span className="text-acc">192.168.1.1</span><span className="text-text-muted"> → </span><span className="text-text-secondary">3 ports open</span></p>
          <p><span className="text-text-muted">[13:41:09] </span><span className="text-acc-warm">CVE-2024-3094</span><span className="text-text-muted"> CVSS </span><span className="text-red-400 font-bold">9.8 CRITICAL</span></p>
          <p><span className="text-text-muted">[13:41:11] </span><span className="text-acc">api.internal:443</span><span className="text-text-muted"> → patch available ✓</span></p>
        </div>

        {/* KPI row */}
        <div className="grid grid-cols-3 gap-2">
          {[
            { value: '247',   label: 'Hosts' },
            { value: '12',    label: 'Critical', valueClassName: 'text-acc-warm' },
            { value: '99.2%', label: 'Uptime' },
          ].map(({ value, label, valueClassName }) => (
            <div key={label} className="bg-prime-900/80 rounded-lg p-2.5 text-center border border-border">
              <MetricStat
                value={value}
                label={label}
                valueClassName={`!text-2xl ${valueClassName ?? ''}`}
                className="items-center"
              />
            </div>
          ))}
        </div>

        {/* Status badges */}
        <div className="flex flex-wrap gap-1.5">
          <Badge variant="red"    dot>CRITICAL ×3</Badge>
          <Badge variant="orange" dot>HIGH ×4</Badge>
          <Badge variant="cyan"   dot>PATCHED ×89</Badge>
        </div>
      </div>
    </PrimeCard>
  )
}

// ── Hero ──────────────────────────────────────────────────────────────────────
export function Hero() {
  return (
    <section className="relative min-h-[90vh] flex items-center overflow-hidden">
      {/* Canvas layers */}
      <GridBackground fade opacity={0.4} />
      <div
        aria-hidden="true"
        className="absolute inset-x-0 top-0 h-[600px] pointer-events-none bg-radial-glow"
      />

      <div className="relative z-10 mx-auto max-w-7xl px-6 md:px-12 w-full">
        <div className="grid lg:grid-cols-[1.2fr_0.8fr] gap-12 items-center py-20 md:py-28">

          {/* ── Left: content ──────────────────────────────────────────── */}
          <motion.div
            variants={container}
            initial="hidden"
            animate="show"
            className="flex flex-col"
          >
            <motion.div variants={item}>
              <Badge variant="cyan">AI-Native Security Platform</Badge>
            </motion.div>

            <motion.h1
              variants={item}
              className="mt-6 text-5xl md:text-7xl lg:text-8xl font-display font-bold tracking-[-0.02em] leading-[1.05] text-white text-balance"
            >
              Protect Every<br />
              <span className="text-acc">Attack Surface</span><br />
              Intelligently.
            </motion.h1>

            <motion.p
              variants={item}
              className="text-lg md:text-xl text-text-secondary max-w-xl mt-6 font-light leading-relaxed"
            >
              Real-time vulnerability intelligence. AI-powered threat scoring.
              Automated remediation workflows — built for modern security teams.
            </motion.p>

            {/* CTA buttons */}
            <motion.div variants={item} className="flex flex-wrap gap-3 mt-10">
              <PrimeButton
                variant="primary"
                size="lg"
                onClick={() => (window.location.href = '/app')}
              >
                See Live Demo
              </PrimeButton>
              <PrimeButton
                variant="ghost"
                size="lg"
                icon={<Play size={16} className="fill-current" />}
                onClick={() => {
                  const el = document.getElementById('solutions')
                  el?.scrollIntoView({ behavior: 'smooth' })
                }}
              >
                Watch Demo
              </PrimeButton>
            </motion.div>

            {/* Trust logos */}
            <motion.div
              variants={item}
              className="mt-16 flex flex-wrap items-center gap-2 opacity-50 hover:opacity-100 transition-opacity duration-slow"
            >
              <span className="text-xs text-text-muted mr-4">Trusted by</span>
              {['Stripe', 'Vercel', 'Linear', 'Notion'].map((name) => (
                <span key={name} className="font-display font-semibold text-sm text-text-secondary">
                  {name}
                </span>
              ))}
            </motion.div>
          </motion.div>

          {/* ── Right: floating product mockup ─────────────────────────── */}
          <motion.div
            initial={{ opacity: 0, x: 40 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.3, ease: [0.16, 1, 0.3, 1] }}
            className="animate-float hidden lg:block"
          >
            <PortalMockup />
          </motion.div>

        </div>
      </div>
    </section>
  )
}

export default Hero
