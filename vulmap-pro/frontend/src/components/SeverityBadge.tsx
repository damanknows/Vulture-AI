import type { CSSProperties } from 'react'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'

const COLORS: Record<Severity, { bg: string; border: string; text: string; dot: string; label: string }> = {
  CRITICAL: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/40',
    text: 'text-red-400',
    dot: 'bg-red-400 shadow-[0_0_6px_rgba(248,113,113,0.8)]',
    label: 'Critical',
  },
  HIGH: {
    bg: 'bg-acc-warm/10',
    border: 'border-acc-warm/40',
    text: 'text-acc-warm',
    dot: 'bg-acc-warm shadow-[0_0_6px_rgba(255,107,53,0.8)]',
    label: 'High',
  },
  MEDIUM: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/40',
    text: 'text-amber-400',
    dot: 'bg-amber-400',
    label: 'Medium',
  },
  LOW: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/40',
    text: 'text-blue-400',
    dot: 'bg-blue-400',
    label: 'Low',
  },
  NONE: {
    bg: 'bg-prime-700/50',
    border: 'border-border',
    text: 'text-text-muted',
    dot: 'bg-text-muted',
    label: 'N/A',
  },
}

interface Props {
  severity?: string | null
  score?: number | null
  style?: CSSProperties
}

/**
 * Color-coded badge for a CVE severity. Falls back to a derived severity
 * from the CVSS v3 score when the API doesn't supply one directly.
 */
export function severityFromScore(score: number | null | undefined): Severity {
  if (score == null) return 'NONE'
  if (score >= 9.0) return 'CRITICAL'
  if (score >= 7.0) return 'HIGH'
  if (score >= 4.0) return 'MEDIUM'
  if (score > 0) return 'LOW'
  return 'NONE'
}

export function SeverityBadge({ severity, score, style }: Props) {
  const sev = ((severity ?? '').toUpperCase() as Severity) || severityFromScore(score ?? null)
  const color = COLORS[sev] ?? COLORS.NONE
  const text = score != null ? `${color.label} · ${score.toFixed(1)}` : color.label

  return (
    <span
      style={style}
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[11px] font-medium select-none ${color.bg} ${color.border} ${color.text}`}
      title={severity ? `Severity ${severity}` : 'Severity derived from CVSS v3 score'}
    >
      <span className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${color.dot}`} />
      {text}
    </span>
  )
}

export default SeverityBadge
