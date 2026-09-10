import { useState } from 'react'
import { Link, Route, Routes, useLocation } from 'react-router-dom'
import { Dashboard } from './components/Dashboard'
import { ScanDetailView } from './components/ScanDetailView'
import { ScanHistory } from './components/ScanHistory'
import { LandingPage } from './components/pages/LandingPage'
import { Badge, GridBackground } from './components/ui'
import { Shield, LayoutDashboard, Home } from 'lucide-react'

function AppShell() {
  const [refreshKey, setRefreshKey] = useState(0)
  const location = useLocation()

  return (
    <div className="min-h-screen bg-prime-950 text-text-primary flex flex-col relative selection:bg-acc/30 selection:text-white">
      <GridBackground opacity={0.2} />

      {/* App Console Top Bar */}
      <header className="sticky top-0 z-40 border-b border-border bg-prime-950/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3.5">
          <div className="flex items-center gap-6">
            <Link to="/" className="flex items-center gap-2.5 group">
              <img
                src="/vulture-logo.jpg"
                alt="Vulture AI"
                className="w-7 h-7 rounded-md object-cover border border-border group-hover:border-acc/40 transition-colors shadow-glow-cyan-sm"
              />
              <span className="font-display font-bold text-lg text-white tracking-tight">Vulture AI</span>
              <Badge variant="cyan" dot={false} size="xs">CONSOLE</Badge>
            </Link>

            <nav className="hidden sm:flex items-center gap-2 text-xs font-mono">
              <Link
                to="/"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-text-secondary hover:text-white hover:bg-prime-800 transition-colors"
              >
                <Home size={13} />
                Overview
              </Link>
              <Link
                to="/app"
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors ${
                  location.pathname === '/app' || location.pathname.startsWith('/scans')
                    ? 'bg-acc-subtle text-acc border border-acc/20 font-medium'
                    : 'text-text-secondary hover:text-white hover:bg-prime-800'
                }`}
              >
                <LayoutDashboard size={13} />
                Scanner
              </Link>
            </nav>
          </div>

          <div className="flex items-center gap-3">
            <span className="hidden md:inline-flex items-center gap-1.5 font-mono text-xs text-text-muted">
              <Shield size={13} className="text-acc" />
              Nmap Engine × NIST NVD
            </span>
            <Link
              to="/app"
              className="px-3 py-1 rounded-lg text-xs font-mono font-medium bg-acc text-prime-950 hover:bg-acc-600 transition-colors"
            >
              + New Scan
            </Link>
          </div>
        </div>
      </header>

      {/* Main App Content Grid */}
      <main className="relative z-10 mx-auto grid max-w-7xl w-full grid-cols-1 gap-6 px-6 py-8 md:grid-cols-[1fr_360px] flex-1">
        <div>
          <Routes>
            <Route path="/" element={<Dashboard onScanQueued={() => setRefreshKey((k) => k + 1)} />} />
            <Route path="/scans/:id" element={<ScanDetailView />} />
          </Routes>
        </div>
        <aside className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-text-secondary">
              Telemetry Log
            </h2>
            <span className="text-[10px] font-mono text-acc animate-pulse">● LIVE</span>
          </div>
          <ScanHistory refreshKey={refreshKey} />
        </aside>
      </main>
    </div>
  )
}

/**
 * Root routing:
 * - `/` -> PrimeSec High-Conversion SaaS Landing Page
 * - `/app/*` -> Vulnerability Scanner Console
 * - `/scans/:id` -> Detailed Scan telemetry view
 */
export default function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/app/*" element={<AppShell />} />
      <Route path="/scans/:id" element={<AppShell />} />
    </Routes>
  )
}
