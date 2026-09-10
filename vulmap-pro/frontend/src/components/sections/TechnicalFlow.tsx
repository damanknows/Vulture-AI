/**
 * TechnicalFlow.tsx — "How It Works" horizontal timeline.
 * Desktop: horizontal node-connector layout with animated SVG dashed lines.
 * Mobile:  vertical stacked layout with left-border accent.
 * Each step has a code snippet card with basic syntax highlighting.
 */

import { motion, useInView } from 'framer-motion'
import { useRef } from 'react'
import { Badge, GridBackground } from '../ui'

interface Step {
  num: string
  title: string
  desc: string
  code: string
}

const STEPS: Step[] = [
  {
    num: '01',
    title: 'Asset Discovery',
    desc: 'Continuous Nmap scanning of your entire IP space — cloud, on-prem, and shadow IT.',
    code: `// Auto-discover all assets
await scanner.discover({
  cidr: '10.0.0.0/8',
  ports: 'top-1000',
});`,
  },
  {
    num: '02',
    title: 'CVE Matching',
    desc: 'Real-time NVD correlation with ML severity scoring against 200,000+ known vulnerabilities.',
    code: `const cves = await engine.match(fingerprint);
// ML score: 9.8 CRITICAL
console.log(cves[0].cvssV3);`,
  },
  {
    num: '03',
    title: 'Threat Scoring',
    desc: 'Contextual risk assessment factoring exposure, exploitability, and asset criticality.',
    code: `const threat = await engine.analyze(payload);
if (threat.score > 85) {
  await autoBlock(threat.id);
}`,
  },
  {
    num: '04',
    title: 'Auto-Remediation',
    desc: 'One-click patches and firewall rule deployment with full audit trail and rollback.',
    code: `await remediate.apply({
  cveId: 'CVE-2024-1337',
  mode: 'auto',
  notify: ['soc@corp.com'],
});`,
  },
]

// ── Keyword highlighter (simple token split) ─────────────────────────────────
function CodeBlock({ code }: { code: string }) {
  const KEYWORDS = ['await', 'const', 'if', 'async', 'return', 'true', 'false']
  const STRINGS  = /('.*?'|".*?")/g

  // Split on string literals first, then keywords
  const lines = code.split('\n').map((line, li) => {
    // Tokenise: strings first
    const parts: { text: string; kind: 'keyword' | 'string' | 'comment' | 'plain' }[] = []
    let rest = line

    if (rest.trimStart().startsWith('//')) {
      parts.push({ text: rest, kind: 'comment' })
    } else {
      // replace strings temporarily
      const strMatches: string[] = []
      rest = rest.replace(STRINGS, (m) => { strMatches.push(m); return `\x00${strMatches.length - 1}\x00` })

      rest.split(' ').forEach((word) => {
        if (KEYWORDS.includes(word.replace(/[^a-z]/gi, ''))) {
          parts.push({ text: word + ' ', kind: 'keyword' })
        } else {
          // restore string placeholders
          const restored = word.replace(/\x00(\d+)\x00/g, (_, i) => strMatches[Number(i)])
          const isStr = STRINGS.test(restored)
          STRINGS.lastIndex = 0
          parts.push({ text: restored + ' ', kind: isStr ? 'string' : 'plain' })
        }
      })
    }

    return (
      <div key={li}>
        {parts.map((p, pi) => {
          const cls =
            p.kind === 'keyword' ? 'text-acc'
            : p.kind === 'string'  ? 'text-green-400'
            : p.kind === 'comment' ? 'text-text-muted italic'
            : 'text-text-secondary'
          return <span key={pi} className={cls}>{p.text}</span>
        })}
      </div>
    )
  })

  return (
    <div className="mt-4 bg-prime-900 rounded-xl p-4 border border-border overflow-x-auto">
      <pre className="font-mono text-xs leading-relaxed">{lines}</pre>
    </div>
  )
}

// ── Animated SVG connector (desktop) ─────────────────────────────────────────
function AnimatedConnector({ delay = 0 }: { delay?: number }) {
  const ref   = useRef<SVGLineElement>(null)
  const inView = useInView(ref, { once: true, margin: '-100px' })

  return (
    <svg
      className="absolute top-5 h-px overflow-visible"
      style={{ left: '40px', width: 'calc(100% - 20px)' }}
      aria-hidden="true"
    >
      {/* Static dashed base */}
      <line
        x1="0" y1="0" x2="100%" y2="0"
        stroke="rgba(255,255,255,0.06)"
        strokeWidth="1"
        strokeDasharray="4 4"
      />
      {/* Animated accent overlay */}
      <motion.line
        ref={ref}
        x1="0" y1="0" x2="100%" y2="0"
        stroke="rgba(0,245,212,0.4)"
        strokeWidth="1"
        strokeDasharray="4 4"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={inView ? { pathLength: 1, opacity: 1 } : {}}
        transition={{ duration: 1.2, delay, ease: 'easeInOut' }}
      />
    </svg>
  )
}

// ── Section ───────────────────────────────────────────────────────────────────
export function TechnicalFlow() {
  return (
    <section className="relative py-20 md:py-28 overflow-hidden">
      <GridBackground fade opacity={0.3} />

      <div className="relative z-10 max-w-7xl mx-auto px-6 md:px-12">

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-2xl mx-auto mb-16"
        >
          <Badge variant="cyan">How It Works</Badge>
          <h2 className="mt-4 text-4xl md:text-5xl font-display font-bold tracking-tight text-white text-balance">
            From Scan to Shield<br />in Minutes
          </h2>
          <p className="mt-4 text-text-secondary leading-relaxed">
            A fully automated pipeline — from raw network data to blocked threats — with a complete audit trail.
          </p>
        </motion.div>

        {/* ── Desktop: horizontal timeline ─────────────────────────────── */}
        <div className="hidden md:flex items-start gap-0">
          {STEPS.map((step, i) => (
            <div key={step.num} className="flex-1 relative min-w-0">
              {/* Connector between steps */}
              {i < STEPS.length - 1 && (
                <AnimatedConnector delay={i * 0.3} />
              )}

              <motion.div
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-100px' }}
                transition={{ duration: 0.5, delay: i * 0.12, ease: [0.16, 1, 0.3, 1] }}
                className="pr-6"
              >
                {/* Number circle */}
                <div className="w-10 h-10 rounded-full border-2 border-acc/30 bg-prime-800 flex items-center justify-center font-mono text-sm text-acc font-bold shrink-0">
                  {step.num}
                </div>

                {/* Text */}
                <h3 className="mt-4 text-base font-semibold text-white">{step.title}</h3>
                <p className="mt-1 text-sm text-text-secondary leading-relaxed">{step.desc}</p>

                {/* Code card */}
                <CodeBlock code={step.code} />
              </motion.div>
            </div>
          ))}
        </div>

        {/* ── Mobile: vertical timeline ─────────────────────────────────── */}
        <div className="flex md:hidden flex-col gap-0">
          {STEPS.map((step, i) => (
            <div key={step.num} className="flex gap-4">
              {/* Left: number + connector */}
              <div className="flex flex-col items-center shrink-0">
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={{ once: true, margin: '-80px' }}
                  transition={{ duration: 0.4, delay: i * 0.1 }}
                  className="w-10 h-10 rounded-full border-2 border-acc/30 bg-prime-800 flex items-center justify-center font-mono text-sm text-acc font-bold"
                >
                  {step.num}
                </motion.div>
                {i < STEPS.length - 1 && (
                  <div className="w-px flex-1 my-2 bg-border min-h-[2rem]" />
                )}
              </div>

              {/* Right: content */}
              <motion.div
                initial={{ opacity: 0, x: 16 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true, margin: '-80px' }}
                transition={{ duration: 0.5, delay: i * 0.1, ease: [0.16, 1, 0.3, 1] }}
                className="flex-1 pb-6"
              >
                <h3 className="text-base font-semibold text-white mt-2">{step.title}</h3>
                <p className="mt-1 text-sm text-text-secondary leading-relaxed">{step.desc}</p>
                <CodeBlock code={step.code} />
              </motion.div>
            </div>
          ))}
        </div>

      </div>
    </section>
  )
}

export default TechnicalFlow
