import { type HTMLAttributes, type ReactNode } from 'react'
import { useCountUp } from '../../hooks/useCountUp'

/**
 * MetricStat — large-display KPI block for dashboards and hero sections.
 *
 * Renders a vertically stacked:
 *   [optional prefix] + value + [optional suffix]
 *   label
 *   [optional trend line]
 *
 * The value uses `font-display` (Space Grotesk) for maximum visual impact.
 */

type TrendDirection = 'up' | 'down' | 'neutral'

interface Trend {
  /** Formatted change string, e.g. "+12" or "-3%". */
  value: string
  /**
   * Semantic direction controls colour:
   *  `up` = green (improvement) | `down` = red (regression) | `neutral` = muted
   */
  direction: TrendDirection
  /** Optional trailing label, e.g. "vs last scan". */
  label?: string
}

interface MetricStatProps extends HTMLAttributes<HTMLDivElement> {
  /** The primary numeric or text value. */
  value: ReactNode
  /** If provided, will count up from 0 to target on scroll into view. */
  countUpTo?: number
  /** Decimals for countUp. @default 0 */
  decimals?: number
  /** Descriptive label below the value. */
  label: string
  /** Small string appended after the value (e.g. "ms", "%"). */
  suffix?: string
  /** Small string prepended before the value (e.g. "$", "#"). */
  prefix?: string
  /** Optional trend indicator row. */
  trend?: Trend
  /** Override classes on the value element (e.g. different colour). */
  valueClassName?: string
  /** Loading skeleton state. */
  loading?: boolean
}

const trendColours: Record<TrendDirection, string> = {
  up:      'text-green-400',
  down:    'text-red-400',
  neutral: 'text-text-muted',
}

// Arrow icons for trend direction
function TrendArrow({ direction }: { direction: TrendDirection }) {
  if (direction === 'neutral') {
    return (
      <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M2 8h12M8 3l5 5-5 5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    )
  }
  return (
    <svg
      className="h-3.5 w-3.5"
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      style={direction === 'down' ? { transform: 'rotate(180deg)' } : undefined}
    >
      <path
        d="M8 13V3M3 8l5-5 5 5"
        stroke="currentColor"
        strokeWidth="1.5"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// Skeleton shimmer block
function Skeleton({ className = '' }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={[
        'animate-pulse rounded bg-prime-700',
        className,
      ].join(' ')}
    />
  )
}

function AnimatedValue({ target, decimals = 0 }: { target: number; decimals?: number }) {
  const { count, ref } = useCountUp(target, { decimals })
  return <span ref={ref}>{count.toLocaleString()}</span>
}

export function MetricStat({
  value,
  countUpTo,
  decimals = 0,
  label,
  suffix,
  prefix,
  trend,
  valueClassName = '',
  loading = false,
  className = '',
  ...props
}: MetricStatProps) {
  return (
    <div className={['flex flex-col', className].join(' ')} {...props}>
      {/* ── Primary value ─────────────────────────────────────────────── */}
      {loading ? (
        <Skeleton className="h-12 w-32" />
      ) : (
        <div
          className={[
            'flex items-baseline gap-1',
            'text-4xl md:text-5xl font-display font-bold tracking-tight text-white',
            valueClassName,
          ]
            .filter(Boolean)
            .join(' ')}
        >
          {prefix && (
            <span className="text-2xl md:text-3xl text-text-secondary font-medium">
              {prefix}
            </span>
          )}
          {typeof countUpTo === 'number' ? (
            <AnimatedValue target={countUpTo} decimals={decimals} />
          ) : (
            <span>{value}</span>
          )}
          {suffix && (
            <span className="text-xl md:text-2xl text-text-secondary font-medium">
              {suffix}
            </span>
          )}
        </div>
      )}

      {/* ── Label ────────────────────────────────────────────────────── */}
      {loading ? (
        <Skeleton className="mt-2 h-4 w-24" />
      ) : (
        <p className="mt-1 text-sm font-medium text-text-secondary">
          {label}
        </p>
      )}

      {/* ── Trend ────────────────────────────────────────────────────── */}
      {trend && !loading && (
        <div
          className={[
            'mt-2 flex items-center gap-1 text-sm',
            trendColours[trend.direction],
          ].join(' ')}
        >
          <TrendArrow direction={trend.direction} />
          <span className="font-medium">{trend.value}</span>
          {trend.label && (
            <span className="text-text-muted">{trend.label}</span>
          )}
        </div>
      )}
    </div>
  )
}

export default MetricStat
