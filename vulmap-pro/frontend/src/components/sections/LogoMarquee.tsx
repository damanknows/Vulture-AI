/**
 * LogoMarquee.tsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Infinite-scroll logo marquee section.
 * Two duplicate strips run side-by-side inside a w-[200%] flex container so
 * the CSS `marquee` animation (translate -50%) creates a seamless loop.
 * Hover over the marquee track to pause playback.
 * Left/right edges are faded with pseudo-element gradients.
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ─── Logo data ────────────────────────────────────────────────────────────────
const LOGOS: { name: string }[] = [
  { name: 'Stripe'    },
  { name: 'Vercel'    },
  { name: 'Linear'    },
  { name: 'Notion'    },
  { name: 'Figma'     },
  { name: 'GitHub'    },
  { name: 'Datadog'   },
  { name: 'Elastic'   },
  { name: 'HashiCorp' },
  { name: 'Supabase'  },
]

// ─── Single logo item ─────────────────────────────────────────────────────────
function LogoItem({ name }: { name: string }) {
  return (
    <div
      className={[
        'grayscale opacity-40 hover:grayscale-0 hover:opacity-100',
        'transition-all duration-slow cursor-pointer whitespace-nowrap',
        'font-display font-bold text-xl text-white select-none',
      ].join(' ')}
    >
      {name}
    </div>
  )
}

// ─── One marquee strip (rendered twice for seamless loop) ─────────────────────
function MarqueeStrip() {
  return (
    <div className="flex items-center gap-16 animate-marquee group-hover:[animation-play-state:paused]">
      {LOGOS.map((logo) => (
        <LogoItem key={logo.name} name={logo.name} />
      ))}
    </div>
  )
}

// ─── Exported component ───────────────────────────────────────────────────────
export function LogoMarquee() {
  return (
    <div className="relative py-12 md:py-16 border-y border-border overflow-hidden">
      {/* Section label */}
      <p className="text-center text-xs font-mono uppercase tracking-widest text-text-muted mb-8">
        Trusted by security teams at
      </p>

      {/*
       * Marquee track
       * — outer wrapper: clips overflow + provides `group` context for hover-pause
       * — pseudo-elements on the relative wrapper fade left/right edges
       */}
      <div
        className={[
          'group relative overflow-hidden',
          'before:absolute before:inset-y-0 before:left-0 before:w-32',
          'before:bg-gradient-to-r before:from-prime-950 before:to-transparent before:z-10',
          'after:absolute after:inset-y-0 after:right-0 after:w-32',
          'after:bg-gradient-to-l after:from-prime-950 after:to-transparent after:z-10',
        ].join(' ')}
      >
        {/*
         * w-[200%] flex container holds two identical strips.
         * The `marquee` keyframe translates by -50% (= one full strip width)
         * so the second strip seamlessly replaces the first.
         */}
        <div className="flex w-[200%]">
          <MarqueeStrip />
          <MarqueeStrip />
        </div>
      </div>
    </div>
  )
}

export default LogoMarquee
