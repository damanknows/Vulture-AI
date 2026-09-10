import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, type ScanState, type ScanSummary } from '../api'
import { Badge, PrimeCard } from './ui'

const STATE_BADGE: Record<ScanState, { variant: 'cyan' | 'orange' | 'red' | 'gray'; dot: boolean }> = {
  queued:    { variant: 'gray',   dot: true },
  running:   { variant: 'orange', dot: true },
  completed: { variant: 'cyan',   dot: true },
  failed:    { variant: 'red',    dot: true },
}

/**
 * List of past scans with their states and a link to the detail view.
 */
export function ScanHistory({ refreshKey }: { refreshKey?: number }) {
  const [scans, setScans] = useState<ScanSummary[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .listScans()
      .then((rows) => !cancelled && setScans(rows))
      .catch((err) => !cancelled && setError(err.message ?? 'failed to load scans'))
    return () => {
      cancelled = true
    }
  }, [refreshKey])

  if (error) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 font-mono text-xs text-red-400">
        {error}
      </div>
    )
  }
  if (scans == null) {
    return (
      <div className="rounded-lg border border-border bg-prime-800/40 p-4 font-mono text-xs text-text-muted animate-pulse">
        Loading scan history…
      </div>
    )
  }
  if (scans.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-prime-800/40 p-4 text-xs text-text-muted">
        No scans yet. Launch one from the console.
      </div>
    )
  }

  return (
    <PrimeCard noPadding className="overflow-hidden border border-border bg-prime-800/60">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-prime-900/80 font-mono uppercase text-text-muted border-b border-border text-[10px]">
            <tr>
              <th className="px-3 py-2.5">ID</th>
              <th className="px-3 py-2.5">Target</th>
              <th className="px-3 py-2.5">Status</th>
              <th className="px-3 py-2.5 text-center">Hosts</th>
              <th className="px-3 py-2.5 text-center">CVEs</th>
              <th className="px-3 py-2.5 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {scans.map((s) => {
              const badgeCfg = STATE_BADGE[s.state] || STATE_BADGE.queued
              return (
                <tr key={s.id} className="transition-colors hover:bg-prime-700/40 font-mono">
                  <td className="px-3 py-2.5 text-text-muted">#{s.id}</td>
                  <td className="px-3 py-2.5 text-text-primary font-medium">{s.target}</td>
                  <td className="px-3 py-2.5">
                    <Badge variant={badgeCfg.variant} dot={badgeCfg.dot} size="xs">
                      {s.state.toUpperCase()}
                    </Badge>
                  </td>
                  <td className="px-3 py-2.5 text-center text-text-secondary">{s.host_count}</td>
                  <td className="px-3 py-2.5 text-center">
                    <span className={s.vulnerability_count > 0 ? 'text-acc-warm font-bold' : 'text-text-muted'}>
                      {s.vulnerability_count}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <Link
                      to={`/scans/${s.id}`}
                      className="text-acc hover:underline inline-flex items-center gap-0.5"
                    >
                      View →
                    </Link>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </PrimeCard>
  )
}

export default ScanHistory
