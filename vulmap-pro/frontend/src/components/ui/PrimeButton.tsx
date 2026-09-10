import { type ButtonHTMLAttributes, forwardRef } from 'react'

/**
 * PrimeButton — multi-variant CTA button with loading state.
 *
 * Variants:
 *  - `primary` — Electric Cyan fill, dark text, glow on hover
 *  - `ghost`   — transparent with border, accents on hover
 *  - `danger`  — Warm Orange fill for destructive actions
 *
 * Loading state renders a spinner that inherits the current text colour.
 *
 * Usage:
 * ```tsx
 * <PrimeButton>Scan</PrimeButton>
 * <PrimeButton variant="ghost" loading>Scanning…</PrimeButton>
 * <PrimeButton variant="danger" size="sm">Delete</PrimeButton>
 * ```
 */

export type ButtonVariant = 'primary' | 'ghost' | 'danger'
export type ButtonSize    = 'sm' | 'md' | 'lg'

interface PrimeButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** @default 'primary' */
  variant?: ButtonVariant
  /** @default 'md' */
  size?: ButtonSize
  /** Shows a spinner and disables interaction. */
  loading?: boolean
  /** Optional leading icon — rendered before children. */
  icon?: React.ReactNode
}

// ── Variant styles ────────────────────────────────────────────────────────────
const variantStyles: Record<ButtonVariant, string> = {
  primary: [
    'bg-acc text-prime-950 font-medium',
    'hover:bg-acc-600 hover:shadow-glow-cyan',
    'active:bg-acc-700',
    'disabled:bg-acc/40 disabled:cursor-not-allowed',
  ].join(' '),

  ghost: [
    'bg-transparent text-text-secondary font-medium',
    'border border-border',
    'hover:bg-prime-800 hover:border-acc/50 hover:text-text-primary',
    'active:bg-prime-700',
    'disabled:opacity-40 disabled:cursor-not-allowed',
  ].join(' '),

  danger: [
    'bg-acc-warm text-white font-medium',
    'hover:brightness-110 hover:shadow-glow-warm',
    'active:brightness-90',
    'disabled:opacity-40 disabled:cursor-not-allowed',
  ].join(' '),
}

// ── Size styles ───────────────────────────────────────────────────────────────
const sizeStyles: Record<ButtonSize, string> = {
  sm: 'h-8  px-3   text-xs  gap-1.5 rounded-md',
  md: 'h-10 px-5   text-sm  gap-2   rounded-lg',
  lg: 'h-12 px-6   text-base gap-2.5 rounded-xl',
}

// ── Spinner ───────────────────────────────────────────────────────────────────
function Spinner() {
  return (
    <svg
      aria-hidden="true"
      className="h-4 w-4 animate-spin"
      viewBox="0 0 24 24"
      fill="none"
    >
      <circle
        className="opacity-25"
        cx="12" cy="12" r="10"
        stroke="currentColor"
        strokeWidth="3"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  )
}

export const PrimeButton = forwardRef<HTMLButtonElement, PrimeButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      loading = false,
      icon,
      disabled,
      className = '',
      children,
      ...props
    },
    ref,
  ) => {
    const isDisabled = disabled || loading

    return (
      <button
        ref={ref}
        disabled={isDisabled}
        aria-busy={loading || undefined}
        className={[
          // ── Base ─────────────────────────────────────────────────────────
          'inline-flex items-center justify-center leading-none',
          'transition-all ease-expo',
          'duration-normal',
          'focus-visible:outline-none',
          'focus-visible:ring-2 focus-visible:ring-acc/50 focus-visible:ring-offset-2',
          'focus-visible:ring-offset-prime-950',
          'select-none',
          // Scale down on press (only when not disabled)
          !isDisabled && 'active:scale-[0.97]',
          // ── Variant + Size ───────────────────────────────────────────────
          variantStyles[variant],
          sizeStyles[size],
          className,
        ]
          .filter(Boolean)
          .join(' ')}
        {...props}
      >
        {/* Loading spinner replaces icon */}
        {loading ? <Spinner /> : icon && <span className="shrink-0">{icon}</span>}

        {children && (
          <span className={loading ? 'opacity-70' : undefined}>{children}</span>
        )}
      </button>
    )
  },
)

PrimeButton.displayName = 'PrimeButton'

export default PrimeButton
