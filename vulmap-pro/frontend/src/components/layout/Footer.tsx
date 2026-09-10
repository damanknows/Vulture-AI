import { useState } from 'react'
import { CheckCheck } from 'lucide-react'
import { PrimeButton, PrimeInput, GridBackground } from '../ui'

// ─── Link-column data ─────────────────────────────────────────────────────────
interface LinkColumn {
  heading: string
  links: string[]
}

const LINK_COLUMNS: LinkColumn[] = [
  { heading: 'Product', links: ['Features', 'Pricing', 'Changelog', 'API Docs'] },
  { heading: 'Company', links: ['About', 'Blog', 'Careers', 'Press'] },
  { heading: 'Legal',   links: ['Privacy', 'Terms', 'Security', 'Cookies'] },
]

function GithubIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
    </svg>
  )
}

function TwitterIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
    </svg>
  )
}

function LinkedinIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path fillRule="evenodd" clipRule="evenodd" d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.2V10.9H6.46M7.83 6.2a1.64 1.64 0 1 0 0 3.28 1.64 1.64 0 0 0 0-3.28z" />
    </svg>
  )
}

// ─── Reusable link-column ─────────────────────────────────────────────────────
function FooterLinkColumn({ heading, links }: LinkColumn) {
  return (
    <div>
      <p className="text-sm font-semibold text-white mb-4">{heading}</p>
      <ul className="space-y-0.5">
        {links.map((link) => (
          <li key={link}>
            <a
              href="#"
              className="text-sm text-text-muted hover:text-white transition-colors py-0.5 block"
            >
              {link}
            </a>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ─── Social icon button ───────────────────────────────────────────────────────
function SocialIconBtn({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <a
      href="#"
      aria-label={label}
      className={[
        'w-9 h-9 rounded-lg border border-border flex items-center justify-center',
        'text-text-muted hover:text-white hover:border-border-strong transition-colors',
      ].join(' ')}
    >
      {children}
    </a>
  )
}

// ─── Newsletter form ──────────────────────────────────────────────────────────
function NewsletterForm() {
  const [email, setEmail]         = useState('')
  const [loading, setLoading]     = useState(false)
  const [subscribed, setSubscribed] = useState(false)

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (!email.trim() || loading || subscribed) return
    setLoading(true)
    setTimeout(() => {
      setLoading(false)
      setSubscribed(true)
    }, 1500)
  }

  return (
    <div className="border-t border-border mt-8 pt-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
      <div>
        <p className="text-sm font-semibold text-white">Get weekly threat intel</p>
        <p className="text-xs text-text-muted mt-1">No spam. Unsubscribe anytime.</p>
      </div>

      {subscribed ? (
        <span className="text-sm text-acc flex items-center gap-1.5">
          <CheckCheck size={14} />
          Subscribed to threat intel.
        </span>
      ) : (
        <form onSubmit={handleSubmit} className="flex gap-2 items-start w-full md:w-auto">
          <PrimeInput
            type="email"
            placeholder="your@company.com"
            className="w-full md:w-72"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            aria-label="Email address for threat intel newsletter"
          />
          <PrimeButton
            variant="primary"
            size="sm"
            type="submit"
            loading={loading}
          >
            Subscribe
          </PrimeButton>
        </form>
      )}
    </div>
  )
}

// ─── Footer ───────────────────────────────────────────────────────────────────
export function Footer() {
  return (
    <footer className="relative border-t border-border bg-prime-950 pt-16 pb-8 overflow-hidden">
      <GridBackground opacity={0.2} />

      <div className="relative z-10 max-w-7xl mx-auto px-6 md:px-12">
        {/* ── Top grid ───────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-8 mb-12">
          {/* Brand column */}
          <div className="col-span-2 lg:col-span-2">
            <a href="/" className="flex items-center gap-2.5 group w-fit">
              <img
                src="/vulture-logo.jpg"
                alt="Vulture AI"
                className="w-8 h-8 rounded-lg object-cover border border-border group-hover:border-acc/40 transition-all duration-normal shadow-glow-cyan-sm"
              />
              <span className="font-display font-bold text-lg text-white tracking-tight">
                Vulture AI
              </span>
            </a>

            <p className="mt-3 text-sm text-text-muted max-w-xs leading-relaxed">
              Continuous vulnerability intelligence for modern security teams.
            </p>

            <div className="mt-6 flex gap-3">
              <SocialIconBtn label="GitHub">
                <GithubIcon className="w-4 h-4" />
              </SocialIconBtn>
              <SocialIconBtn label="Twitter / X">
                <TwitterIcon className="w-3.5 h-3.5" />
              </SocialIconBtn>
              <SocialIconBtn label="LinkedIn">
                <LinkedinIcon className="w-3.5 h-3.5" />
              </SocialIconBtn>
            </div>
          </div>

          {/* Link columns */}
          {LINK_COLUMNS.map((col) => (
            <FooterLinkColumn key={col.heading} heading={col.heading} links={col.links} />
          ))}
        </div>

        {/* ── Newsletter ─────────────────────────────────────────────────── */}
        <NewsletterForm />

        {/* ── Bottom bar ─────────────────────────────────────────────────── */}
        <div className="border-t border-border mt-8 pt-6 flex flex-col md:flex-row items-center justify-between gap-3">
          <p className="text-xs text-text-muted">
            © 2026 Vulture AI, Inc. All rights reserved.
          </p>

          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-acc opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-acc" />
            </span>
            <span className="text-xs font-mono text-acc">All systems operational</span>
          </div>
        </div>
      </div>
    </footer>
  )
}

export default Footer
