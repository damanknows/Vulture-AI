/**
 * Navbar.tsx — PrimeSec sticky navigation bar.
 * Desktop: logo + nav links + CTA button.
 * Mobile:  hamburger → Framer Motion drawer sliding in from the right.
 * Auto-hide on scroll down, show on scroll up with Framer Motion useScroll.
 */

import { useState, useEffect } from 'react'
import { Menu, X } from 'lucide-react'
import { AnimatePresence, motion, useScroll, useMotionValueEvent } from 'framer-motion'
import { PrimeButton } from '../ui'

const NAV_LINKS = ['Platform', 'Solutions', 'Pricing', 'Docs']

export function Navbar() {
  const [open, setOpen] = useState(false)
  const [hidden, setHidden] = useState(false)
  const { scrollY } = useScroll()

  useMotionValueEvent(scrollY, 'change', (latest) => {
    const previous = scrollY.getPrevious() ?? 0
    if (latest > previous && latest > 150) {
      setHidden(true)
    } else {
      setHidden(false)
    }
  })

  // Close on ESC key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    if (open) {
      document.body.style.overflow = 'hidden'
      window.addEventListener('keydown', handleKeyDown)
    } else {
      document.body.style.overflow = 'unset'
    }
    return () => {
      document.body.style.overflow = 'unset'
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [open])

  return (
    <>
      {/* ── Sticky bar with motion hide/show ──────────────────────────────── */}
      <motion.header
        variants={{
          visible: { y: 0 },
          hidden: { y: '-100%' },
        }}
        animate={hidden ? 'hidden' : 'visible'}
        transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
        className="sticky top-0 z-50 backdrop-blur-2xl bg-prime-950/80 border-b border-border"
      >
        <div className="mx-auto max-w-7xl px-6 md:px-12 h-16 md:h-18 flex items-center justify-between">

          {/* Logo */}
          <a href="/" className="flex items-center gap-2.5 group shrink-0" aria-label="Vulture AI Home">
            <img
              src="/vulture-logo.jpg"
              alt="Vulture AI"
              className="w-8 h-8 rounded-lg object-cover border border-border group-hover:border-acc/40 transition-all duration-normal shadow-glow-cyan-sm"
            />
            <span className="font-display font-bold text-xl text-white tracking-tight">
              Vulture AI
            </span>
          </a>

          {/* Desktop nav */}
          <nav className="hidden md:flex items-center gap-1" aria-label="Primary">
            {NAV_LINKS.map((link) => (
              <a
                key={link}
                href={`#${link.toLowerCase()}`}
                className="px-4 py-2 text-sm text-text-secondary hover:text-white transition-colors duration-fast rounded-lg hover:bg-prime-800"
              >
                {link}
              </a>
            ))}
          </nav>

          {/* Desktop CTA */}
          <div className="hidden md:flex items-center gap-3">
            <a href="/app" className="text-sm text-text-secondary hover:text-white transition-colors duration-fast">
              Sign in
            </a>
            <PrimeButton variant="primary" size="sm" onClick={() => (window.location.href = '/app')}>
              Start Free Trial
            </PrimeButton>
          </div>

          {/* Mobile hamburger */}
          <button
            aria-label={open ? 'Close menu' : 'Open menu'}
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
            className="md:hidden flex items-center justify-center w-9 h-9 rounded-lg border border-border text-text-secondary hover:text-white hover:border-border-strong transition-colors"
          >
            {open ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </motion.header>

      {/* ── Mobile drawer ───────────────────────────────────────────────── */}
      <AnimatePresence>
        {open && (
          <>
            {/* Backdrop */}
            <motion.div
              key="backdrop"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 z-50 bg-prime-950/80 backdrop-blur-md md:hidden"
              onClick={() => setOpen(false)}
            />

            {/* Drawer panel */}
            <motion.div
              key="drawer"
              role="dialog"
              aria-modal="true"
              aria-label="Mobile navigation"
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed inset-y-0 right-0 z-50 w-72 bg-prime-950/95 backdrop-blur-xl border-l border-border flex flex-col md:hidden"
            >
              {/* Drawer header */}
              <div className="flex items-center justify-between px-6 h-16 border-b border-border shrink-0">
                <a href="/" className="flex items-center gap-2.5" onClick={() => setOpen(false)}>
                  <img
                    src="/vulture-logo.jpg"
                    alt="Vulture AI"
                    className="w-8 h-8 rounded-lg object-cover border border-border shadow-glow-cyan-sm"
                  />
                  <span className="font-display font-bold text-lg text-white">Vulture AI</span>
                </a>
                <button
                  aria-label="Close menu"
                  onClick={() => setOpen(false)}
                  className="flex items-center justify-center w-8 h-8 rounded-lg border border-border text-text-secondary hover:text-white transition-colors"
                >
                  <X size={16} />
                </button>
              </div>

              {/* Drawer links */}
              <nav className="flex-1 px-4 py-6 space-y-1" aria-label="Mobile Navigation Links">
                {NAV_LINKS.map((link, i) => (
                  <motion.a
                    key={link}
                    href={`#${link.toLowerCase()}`}
                    initial={{ opacity: 0, x: 16 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.06, duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                    onClick={() => setOpen(false)}
                    className="flex items-center px-4 py-3 rounded-xl text-sm text-text-secondary hover:text-white hover:bg-prime-800 transition-colors duration-fast"
                  >
                    {link}
                  </motion.a>
                ))}
              </nav>

              {/* Drawer CTA */}
              <div className="px-4 pb-8 pt-2 space-y-2 border-t border-border shrink-0">
                <a
                  href="/app"
                  className="flex items-center justify-center px-4 py-2.5 text-sm text-text-secondary hover:text-white transition-colors"
                  onClick={() => setOpen(false)}
                >
                  Sign in
                </a>
                <PrimeButton
                  variant="primary"
                  className="w-full"
                  onClick={() => {
                    setOpen(false)
                    window.location.href = '/app'
                  }}
                >
                  Start Free Trial
                </PrimeButton>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  )
}

export default Navbar
