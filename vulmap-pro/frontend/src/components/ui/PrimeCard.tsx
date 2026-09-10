import { type HTMLAttributes, forwardRef } from 'react'

/**
 * PrimeCard — glassmorphism surface primitive.
 *
 * Variants:
 *  - `default`  — subtle border, no glow
 *  - `accent`   — Electric Cyan glow on border + shadow
 *  - `flat`     — no border, solid `bg-prime-800` (data tables, dense lists)
 *
 * The `::before` shine is rendered via an inner `<div>` since React
 * doesn't support pseudo-element injection in JSX.
 *
 * Usage:
 * ```tsx
 * <PrimeCard>…content…</PrimeCard>
 * <PrimeCard variant="accent" noPadding>…</PrimeCard>
 * ```
 */

type CardVariant = 'default' | 'accent' | 'flat'

interface PrimeCardProps extends HTMLAttributes<HTMLDivElement> {
  /** Visual intensity of the card border/glow. @default 'default' */
  variant?: CardVariant
  /** Strip the default p-6 md:p-8 padding (useful when you need full-bleed children). */
  noPadding?: boolean
  /** Disable the hover lift + glow effect. */
  noHover?: boolean
}

const variantClasses: Record<CardVariant, string> = {
  default:
    'border-border hover:border-acc/30 hover:shadow-glow-cyan-sm',
  accent:
    'border-acc/30 shadow-glow-cyan-sm hover:border-acc/50 hover:shadow-glow-cyan',
  flat:
    'border-transparent bg-prime-800',
}

export const PrimeCard = forwardRef<HTMLDivElement, PrimeCardProps>(
  (
    {
      variant = 'default',
      noPadding = false,
      noHover = false,
      className = '',
      children,
      ...props
    },
    ref,
  ) => {
    return (
      <div
        ref={ref}
        className={[
          // ── Base glass surface ──────────────────────────────────────────
          'relative overflow-hidden rounded-2xl',
          'bg-prime-800/50 backdrop-blur-xl',
          'border',
          'shadow-glass',
          // ── Transition ──────────────────────────────────────────────────
          !noHover && 'transition-all duration-normal ease-expo',
          // ── Variant ─────────────────────────────────────────────────────
          variantClasses[variant],
          // ── Padding ─────────────────────────────────────────────────────
          !noPadding && 'p-6 md:p-8',
          className,
        ]
          .filter(Boolean)
          .join(' ')}
        {...props}
      >
        {/* Inner shine gradient — simulates ::before shine layer */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 rounded-2xl"
          style={{
            background:
              'linear-gradient(135deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0) 60%)',
          }}
        />

        {/* Top-edge highlight line */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-px rounded-t-2xl"
          style={{
            background:
              'linear-gradient(90deg, transparent, rgba(255,255,255,0.08) 30%, rgba(255,255,255,0.08) 70%, transparent)',
          }}
        />

        {/* Content sits above shine layers */}
        <div className="relative">{children}</div>
      </div>
    )
  },
)

PrimeCard.displayName = 'PrimeCard'

export default PrimeCard
