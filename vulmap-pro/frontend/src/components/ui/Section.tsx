import { type HTMLAttributes, forwardRef } from 'react'

/**
 * Section — full-width page section wrapper.
 *
 * Enforces consistent horizontal padding and vertical rhythm across all
 * marketing / dashboard sections. Wrap with a `<GridBackground>` sibling
 * for depth (see `GridBackground`).
 *
 * Usage:
 * ```tsx
 * <Section>
 *   <GridBackground />
 *   <h2>…</h2>
 * </Section>
 *
 * // Narrow inner container:
 * <Section>
 *   <div className="mx-auto max-w-5xl">…</div>
 * </Section>
 * ```
 */

interface SectionProps extends HTMLAttributes<HTMLElement> {
  /** HTML element to render. @default 'section' */
  as?: 'section' | 'div' | 'article' | 'main'
  /**
   * Remove default vertical padding — useful when you're stacking sections
   * and want fine-grained control per section.
   */
  noPaddingY?: boolean
}

/**
 * Polymorphic Section uses a ref cast to HTMLElement so it remains
 * compatible with section/div/article/main without complex generics.
 */
export const Section = forwardRef<HTMLElement, SectionProps>(
  (
    {
      as,
      noPaddingY = false,
      className = '',
      children,
      ...props
    },
    ref,
  ) => {
    const Tag = as ?? 'section'

    return (
      <Tag
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ref={ref as any}
        className={[
          'relative w-full',
          'px-6 md:px-12 lg:px-20',
          !noPaddingY && 'py-20 md:py-28',
          className,
        ]
          .filter(Boolean)
          .join(' ')}
        {...props}
      >
        {children}
      </Tag>
    )
  },
)

Section.displayName = 'Section'

export default Section
