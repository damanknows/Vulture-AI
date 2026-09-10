/**
 * Capabilities.tsx
 * ----------------
 * 3-column capabilities grid section for Vulmap Pro / PrimeSec.
 * Showcases the six core product capabilities with animated cards,
 * dynamic icon rendering, and tag badges.
 */

import React from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Zap,
  Globe,
  Lock,
  BarChart2,
  Bell,
  type LucideIcon,
} from 'lucide-react';
import { Badge, PrimeCard, GridBackground } from '../ui';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Capability {
  icon: keyof typeof iconMap;
  title: string;
  desc: string;
  tags: string[];
}

// ---------------------------------------------------------------------------
// Icon map — maps string keys to Lucide icon components
// ---------------------------------------------------------------------------

const iconMap = {
  Shield,
  Zap,
  Globe,
  Lock,
  BarChart2,
  Bell,
} satisfies Record<string, LucideIcon>;

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

const capabilities: Capability[] = [
  {
    icon: 'Shield',
    title: 'Vulnerability Scanner',
    desc: 'Continuous Nmap-powered scanning with real-time CVE correlation and CVSS v3 scoring.',
    tags: ['Real-time', 'CVSS v3', 'API-First'],
  },
  {
    icon: 'Zap',
    title: 'AI Threat Scoring',
    desc: 'ML models trained on 50M+ threat vectors to predict exploitability before patches are available.',
    tags: ['ML-Powered', 'Predictive', 'Zero-day'],
  },
  {
    icon: 'Globe',
    title: 'Attack Surface Mapping',
    desc: 'Automatically discovers shadow IT, cloud assets, and third-party exposure across your entire perimeter.',
    tags: ['Cloud-Native', 'Auto-Discovery'],
  },
  {
    icon: 'Lock',
    title: 'Auto-Remediation',
    desc: 'One-click patch deployment and firewall rule automation integrated with your existing toolchain.',
    tags: ['1-Click Fix', 'SOAR-Ready'],
  },
  {
    icon: 'BarChart2',
    title: 'Risk Analytics',
    desc: 'Executive-ready dashboards with trend analysis, SLA tracking, and compliance mapping (SOC2, ISO27001).',
    tags: ['SOC2', 'ISO27001', 'Reporting'],
  },
  {
    icon: 'Bell',
    title: 'Intelligent Alerting',
    desc: 'Context-aware alerts that eliminate noise. Notifies only when action is required, with full remediation context.',
    tags: ['Low Noise', 'Slack/Teams', 'Webhooks'],
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function Capabilities(): React.ReactElement {
  return (
    <section className="relative py-20 md:py-28 overflow-hidden">
      {/* Subtle grid pattern behind content */}
      <GridBackground fade />

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="max-w-2xl mx-auto text-center mb-16 px-6">
        <Badge variant="cyan">Core Capabilities</Badge>

        <h2 className="mt-4 text-4xl md:text-5xl font-display font-bold tracking-tight text-white text-balance">
          Security Intelligence,
          <br />
          Unified.
        </h2>

        <p className="mt-4 text-base md:text-lg text-text-secondary leading-relaxed">
          Everything your security team needs — from discovery to remediation —
          in a single, deeply integrated platform.
        </p>
      </div>

      {/* ── Capabilities Grid ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-7xl mx-auto px-6 md:px-12">
        {capabilities.map((cap, index) => {
          const IconComponent = iconMap[cap.icon];

          return (
            <motion.div
              key={cap.title}
              className="group"
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              whileHover={{ y: -2 }}
              viewport={{ once: true, margin: '-100px' }}
              transition={{
                duration: 0.45,
                delay: index * 0.08,
                ease: 'easeOut',
              }}
            >
              {/* PrimeCard variant='default' includes hover:border-acc/30 */}
              <PrimeCard variant="default" className="h-full">
                {/* Icon */}
                <div className="w-10 h-10 rounded-lg bg-acc/10 flex items-center justify-center text-acc transition-all duration-normal group-hover:bg-acc/20 group-hover:scale-110">
                  <IconComponent className="w-5 h-5" aria-hidden="true" />
                </div>

                {/* Title */}
                <h3 className="mt-4 text-lg font-semibold text-white">
                  {cap.title}
                </h3>

                {/* Description */}
                <p className="mt-2 text-sm text-text-secondary leading-relaxed line-clamp-3">
                  {cap.desc}
                </p>

                {/* Tags */}
                <div className="mt-4 flex flex-wrap gap-1.5">
                  {cap.tags.map((tag) => (
                    <Badge key={tag} variant="gray" size="xs">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </PrimeCard>
            </motion.div>
          );
        })}
      </div>
    </section>
  );
}

export default Capabilities;
