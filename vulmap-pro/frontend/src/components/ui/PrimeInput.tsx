import {
  type InputHTMLAttributes,
  type ReactNode,
  forwardRef,
  useId,
} from 'react'

/**
 * PrimeInput — labelled text input following PrimeSec design language.
 *
 * Features:
 *  - Automatic `id` linkage between `<label>` and `<input>` via `useId`
 *  - Optional leading icon (left-inset, non-interactive)
 *  - Optional trailing element (right-inset: clear button, status icon, etc.)
 *  - Error state: red border + helper text
 *  - Hint text below the field
 *
 * Usage:
 * ```tsx
 * <PrimeInput label="Target host" placeholder="192.168.1.1" />
 * <PrimeInput label="Port" type="number" error="Must be 1–65535" />
 * <PrimeInput label="Search" leadingIcon={<SearchIcon />} />
 * ```
 */

interface PrimeInputProps extends InputHTMLAttributes<HTMLInputElement> {
  /** Visible label rendered above the input. */
  label?: string
  /** Hint text rendered below the input in muted style. */
  hint?: string
  /**
   * Error message. When set, the border turns red and the message is
   * rendered below the input (replaces hint).
   */
  error?: string
  /** Icon/element inset on the left side of the input field. */
  leadingIcon?: ReactNode
  /** Icon/element inset on the right side of the input field (e.g. clear button). */
  trailingElement?: ReactNode
  /** Override the auto-generated label `for` / input `id`. */
  inputId?: string
}

export const PrimeInput = forwardRef<HTMLInputElement, PrimeInputProps>(
  (
    {
      label,
      hint,
      error,
      leadingIcon,
      trailingElement,
      inputId,
      className = '',
      disabled,
      ...props
    },
    ref,
  ) => {
    const generatedId = useId()
    const id = inputId ?? generatedId

    const hasError = Boolean(error)

    return (
      <div className="w-full">
        {/* Label */}
        {label && (
          <label
            htmlFor={id}
            className="mb-1.5 block text-sm font-medium text-text-secondary"
          >
            {label}
          </label>
        )}

        {/* Input wrapper — positions leading icon + trailing element */}
        <div className="relative flex items-center">
          {/* Leading icon */}
          {leadingIcon && (
            <span
              aria-hidden="true"
              className="pointer-events-none absolute left-3 flex items-center text-text-muted"
            >
              {leadingIcon}
            </span>
          )}

          <input
            ref={ref}
            id={id}
            disabled={disabled}
            aria-invalid={hasError || undefined}
            aria-describedby={
              error ? `${id}-error` : hint ? `${id}-hint` : undefined
            }
            className={[
              // ── Base ───────────────────────────────────────────────────
              'w-full rounded-lg text-sm',
              'bg-prime-900 text-text-primary',
              'placeholder:text-text-muted',
              'border',
              // ── Padding (accounts for icons) ────────────────────────────
              leadingIcon   ? 'pl-9'  : 'pl-4',
              trailingElement ? 'pr-10' : 'pr-4',
              'py-2.5',
              // ── Border / focus states ────────────────────────────────────
              hasError
                ? 'border-red-500/70 focus:border-red-500 focus:ring-1 focus:ring-red-500/30'
                : 'border-border hover:border-border-strong focus:border-acc focus:ring-1 focus:ring-acc/20',
              // ── Transition ───────────────────────────────────────────────
              'transition-all duration-normal ease-expo',
              'outline-none',
              // ── Disabled ─────────────────────────────────────────────────
              disabled && 'cursor-not-allowed opacity-50',
              className,
            ]
              .filter(Boolean)
              .join(' ')}
            {...props}
          />

          {/* Trailing element */}
          {trailingElement && (
            <span className="absolute right-3 flex items-center text-text-muted">
              {trailingElement}
            </span>
          )}
        </div>

        {/* Error message */}
        {error && (
          <p
            id={`${id}-error`}
            role="alert"
            className="mt-1.5 flex items-center gap-1 text-xs text-red-400"
          >
            <svg
              aria-hidden="true"
              className="h-3.5 w-3.5 shrink-0"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                clipRule="evenodd"
              />
            </svg>
            {error}
          </p>
        )}

        {/* Hint text (only when no error) */}
        {!error && hint && (
          <p
            id={`${id}-hint`}
            className="mt-1.5 text-xs text-text-muted"
          >
            {hint}
          </p>
        )}
      </div>
    )
  },
)

PrimeInput.displayName = 'PrimeInput'

export default PrimeInput
