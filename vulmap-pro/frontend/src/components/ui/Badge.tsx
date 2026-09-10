import { type HTMLAttributes } from 'react'

/**
 * Badge — monospace label chip for status, severity, and category tags.
 *
 * Distinct from the existing `SeverityBadge` which is tightly coupled to CVE
 * severity levels. `Badge` is a general-purpose primitive.
 *
 * Variants:
 *  - `cyan`   — Electric Cyan (default) — active states, success, info
 *  - `orange` — Warm Orange — warning, medium severity
 *  - `red`    — Danger — critical severity, error states
 *  - `gray`   — Neutral — inactive, disabled, N/A
 */

export type BadgeVariant = 'cyan' | 'orange' | 'red' | 'gray'
export type BadgeSize = 'xs' | 'sm' | 'md'

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  /** @default 'cyan' */
  variant?: BadgeVariant
  /** Show a small leading dot indicator. @default true */
  dot?: boolean
  /** @default 'sm' */
  size?: BadgeSize
}

const variantStyles: Record<
  BadgeVariant,
  { container: string; dot: string }
> = {
  cyan: {
    container:
      'border-acc/30 text-acc bg-acc/[0.08]',
    dot: 'bg-acc shadow-[0_0_6px_rgba(0,245,212,0.8)]',
  },
  orange: {
    container:
      'border-acc-warm/30 text-acc-warm bg-acc-warm/[0.08]',
    dot: 'bg-acc-warm shadow-[0_0_6px_rgba(255,107,53,0.8)]',
  },
  red: {
    container:
      'border-red-500/30 text-red-400 bg-red-500/[0.08]',
    dot: 'bg-red-400 shadow-[0_0_6px_rgba(248,113,113,0.8)]',
  },
  gray: {
    container:
      'border-border text-text-muted bg-prime-700/50',
    dot: 'bg-text-muted',
  },
}

const sizeStyles: Record<BadgeSize, string> = {
  xs: 'px-2 py-0.5 text-[10px]',
  sm: 'px-2.5 py-0.5 text-xs',
  md: 'px-3 py-1 text-xs',
}

export function Badge({
  variant = 'cyan',
  dot = true,
  size = 'sm',
  className = '',
  children,
  ...props
}: BadgeProps) {
  const styles = variantStyles[variant]

  return (
    <span
      className={[
        'inline-flex items-center gap-1.5',
        sizeStyles[size],
        'font-mono rounded border select-none',
        styles.container,
        className,
      ]
        .filter(Boolean)
        .join(' ')}
      {...props}
    >
      {dot && (
        <span
          aria-hidden="true"
          className={[
            'inline-block h-1.5 w-1.5 shrink-0 rounded-full',
            styles.dot,
          ].join(' ')}
        />
      )}
      {children}
    </span>
  )
}

export default Badge
