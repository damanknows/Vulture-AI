/**
 * Pricing.tsx
 * -----------
 * Three-tier pricing section for Vulmap Pro / PrimeSec.
 * Displays Starter / Pro / Enterprise plans with animated cards,
 * feature lists, and a lifted "Most Popular" center card.
 */

import React from 'react';
import { motion } from 'framer-motion';
import { CheckCheck } from 'lucide-react';
import {
  Badge,
  PrimeCard,
  PrimeButton,
  GridBackground,
} from '../ui';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ButtonVariant = 'primary' | 'ghost';

interface PricingTier {
  name: string;
  price: string;
  period: string;
  description: string;
  features: string[];
  cta: string;
  variant: ButtonVariant;
  popular: boolean;
}

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

const tiers: PricingTier[] = [
  {
    name: 'Starter',
    price: '$0',
    period: '/mo',
    description: 'For solo researchers and small teams getting started.',
    features: [
      'Up to 50 hosts',
      '5 scans/day',
      'CVE correlation',
      'Community support',
      '7-day data retention',
    ],
    cta: 'Get Started Free',
    variant: 'ghost',
    popular: false,
  },
  {
    name: 'Pro',
    price: '$149',
    period: '/mo',
    description: 'For growing security teams with production infrastructure.',
    features: [
      'Unlimited hosts',
      'Continuous scanning',
      'AI threat scoring',
      'Auto-remediation',
      'Slack/Teams alerts',
      'SOC2 reports',
      '1-year data retention',
      'Priority support',
    ],
    cta: 'Start 14-Day Trial',
    variant: 'primary',
    popular: true,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    description: 'For large organizations with advanced compliance needs.',
    features: [
      'Everything in Pro',
      'SSO / SAML',
      'Custom integrations',
      'Dedicated CSM',
      'SLA guarantee',
      'On-premise option',
      'Unlimited retention',
      'White-glove onboarding',
    ],
    cta: 'Contact Sales',
    variant: 'ghost',
    popular: false,
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function Pricing(): React.ReactElement {
  return (
    <section className="relative py-20 md:py-28 overflow-hidden">
      {/* Grid texture */}
      <GridBackground fade />

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="max-w-2xl mx-auto text-center px-6">
        <Badge variant="cyan">Pricing</Badge>

        <h2 className="mt-4 text-4xl md:text-5xl font-display font-bold tracking-tight text-white text-balance">
          Simple, Transparent Pricing
        </h2>

        <p className="mt-4 text-base md:text-lg text-text-secondary leading-relaxed">
          Start free, scale as you grow. No hidden fees, no surprise invoices —
          just powerful security tooling at every tier.
        </p>
      </div>

      {/* ── Pricing Grid ────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl mx-auto px-6 md:px-12 mt-16 items-start">
        {tiers.map((tier, index) => (
          <motion.div
            key={tier.name}
            initial={{ opacity: 0, y: 28 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{
              duration: 0.5,
              delay: index * 0.1,
              ease: 'easeOut',
            }}
          >
            <PrimeCard
              variant={tier.popular ? 'accent' : 'default'}
              className={
                tier.popular
                  ? 'relative md:-mt-4 md:mb-4'
                  : 'relative'
              }
            >
              {/* ── Popular Ribbon ── */}
              {tier.popular && (
                <span className="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-acc text-prime-950 text-xs font-bold px-4 py-1 rounded-full whitespace-nowrap">
                  Most Popular
                </span>
              )}

              {/* ── Plan Name ── */}
              <p className="text-sm font-mono font-medium text-text-secondary uppercase tracking-widest">
                {tier.name}
              </p>

              {/* ── Price ── */}
              <div className="mt-4 flex items-end gap-1">
                <span className="text-5xl font-display font-bold text-white">
                  {tier.price}
                </span>
                {tier.period && (
                  <span className="text-lg text-text-muted mb-1">
                    {tier.period}
                  </span>
                )}
              </div>

              {/* ── Description ── */}
              <p className="mt-3 text-sm text-text-secondary">
                {tier.description}
              </p>

              {/* ── Divider ── */}
              <div className="my-6 border-t border-border" />

              {/* ── Features List ── */}
              <ul className="space-y-3">
                {tier.features.map((feature) => (
                  <li
                    key={feature}
                    className="flex items-start gap-2.5 text-sm text-text-secondary"
                  >
                    <CheckCheck
                      className="text-acc shrink-0 mt-0.5 w-4 h-4"
                      aria-hidden="true"
                    />
                    {feature}
                  </li>
                ))}
              </ul>

              {/* ── CTA Button ── */}
              <PrimeButton
                variant={tier.variant}
                size="md"
                className="w-full mt-8"
              >
                {tier.cta}
              </PrimeButton>

              {/* ── No lock-in note ── */}
              <p className="mt-4 text-center text-xs text-text-muted">
                No vendor lock-in. Cancel anytime.
              </p>
            </PrimeCard>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

export default Pricing;
