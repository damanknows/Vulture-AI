import { Navbar } from '../layout/Navbar'
import { Footer } from '../layout/Footer'
import { Hero } from '../sections/Hero'
import { LogoMarquee } from '../sections/LogoMarquee'
import { AttackMap } from '../sections/AttackMap'
import { Capabilities } from '../sections/Capabilities'
import { TechnicalFlow } from '../sections/TechnicalFlow'
import { Pricing } from '../sections/Pricing'

export function LandingPage() {
  return (
    <div className="min-h-screen bg-prime-950 text-text-primary flex flex-col selection:bg-acc/30 selection:text-white">
      {/* ── Navigation ─────────────────────────────────────────────────── */}
      <Navbar />

      {/* ── Main Content Landmark ──────────────────────────────────────── */}
      <main id="main-content" className="flex-1">
        {/* 1. Hero Section */}
        <Hero />

        {/* 2. Social Proof Marquee */}
        <LogoMarquee />

        {/* 3. Real-time Attack Map / Data Viz */}
        <div id="solutions">
          <AttackMap />
        </div>

        {/* 4. Core Capability Grid */}
        <div id="platform">
          <Capabilities />
        </div>

        {/* 5. How It Works / Technical Flow */}
        <div id="docs">
          <TechnicalFlow />
        </div>

        {/* 6. Pricing Plans */}
        <div id="pricing">
          <Pricing />
        </div>
      </main>

      {/* ── Footer ─────────────────────────────────────────────────────── */}
      <Footer />
    </div>
  )
}

export default LandingPage
