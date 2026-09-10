import { type HTMLAttributes } from 'react'

/**
 * GridBackground — absolute-positioned cyber grid overlay.
 *
 * Renders the `bg-grid-pattern` token as a fixed `40px × 40px` grid with
 * 50% opacity. Place it as the **first child** of a `relative`-positioned
 * parent (e.g. `<Section>` or `<PrimeCard noPadding>`).
 *
 * Optionally add a radial fade-out mask so the grid softens at the edges.
 *
 * Usage:
 * ```tsx
 * <Section>
 *   <GridBackground />
 *   <div className="relative z-10">Content above the grid</div>
 * </Section>
 *
 * // Edge-faded variant:
 * <GridBackground fade />
 * ```
 */

interface GridBackgroundProps extends HTMLAttributes<HTMLDivElement> {
  /**
   * Apply a radial gradient mask that fades the grid out toward the edges.
   * @default false
   */
  fade?: boolean
  /**
   * Grid cell size. @default '40px 40px'
   */
  cellSize?: string
  /**
   * Opacity of the grid lines. @default 0.5
   */
  opacity?: number
}

export function GridBackground({
  fade = false,
  cellSize = '40px 40px',
  opacity = 0.5,
  className = '',
  style,
  ...props
}: GridBackgroundProps) {
  return (
    <div
      aria-hidden="true"
      className={[
        'pointer-events-none select-none',
        'absolute inset-0',
        'bg-grid-pattern',
        className,
      ]
        .filter(Boolean)
        .join(' ')}
      style={{
        backgroundSize: cellSize,
        opacity,
        // Radial gradient mask — fades grid to transparent at the edges
        ...(fade && {
          WebkitMaskImage:
            'radial-gradient(ellipse 70% 70% at 50% 50%, black 40%, transparent 100%)',
          maskImage:
            'radial-gradient(ellipse 70% 70% at 50% 50%, black 40%, transparent 100%)',
        }),
        ...style,
      }}
      {...props}
    />
  )
}

export default GridBackground
