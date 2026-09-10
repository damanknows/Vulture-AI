import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, type ScanDetail } from '../api'
import { HostTable } from './HostTable'
import { Badge, PrimeCard, MetricStat } from './ui'
import { ArrowLeft, Clock, RefreshCw } from 'lucide-react'

const POLL_MS = 2000

export function ScanDetailView() {
  const { id } = useParams<{ id: string }>()
  const scanId = Number(id)
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!Number.isFinite(scanId)) {
      setError('invalid scan id')
      return
    }
    let cancelled = false
    let timer: number | null = null

    async function tick() {
      try {
        const data = await api.getScan(scanId)
        if (cancelled) return
        setScan(data)
        if (data.state === 'queued' || data.state === 'running') {
          timer = window.setTimeout(tick, POLL_MS)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'failed to load scan')
        }
      }
    }

    tick()
    return () => {
      cancelled = true
      if (timer != null) window.clearTimeout(timer)
    }
  }, [scanId])

  if (error) {
    return (
      <div className="space-y-4">
        <Link to="/app" className="inline-flex items-center gap-1 text-sm text-acc hover:underline font-mono">
          <ArrowLeft size={14} /> Back to console
        </Link>
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 font-mono text-xs text-red-400">
          {error}
        </div>
      </div>
    )
  }
  if (!scan) {
    return (
      <div className="rounded-xl border border-border bg-prime-800/40 p-8 text-center font-mono text-xs text-text-muted animate-pulse">
        Fetching scan #{scanId} telemetry…
      </div>
    )
  }

  const isTerminal = scan.state === 'completed' || scan.state === 'failed'

  const durationSec =
    scan.started_at && scan.finished_at
      ? Math.max(
          0,
          Math.round(
            (new Date(scan.finished_at).getTime() -
              new Date(scan.started_at).getTime()) /
              1000,
          ),
        )
      : null

  return (
    <div className="space-y-6">
      <div>
        <Link to="/app" className="inline-flex items-center gap-1.5 text-xs text-text-secondary hover:text-white transition-colors font-mono">
          <ArrowLeft size={14} /> Back to console
        </Link>
      </div>

      <PrimeCard variant="accent" className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-xs text-text-muted">SCAN ID #{scan.id}</span>
              <Badge
                variant={
                  scan.state === 'completed'
                    ? 'cyan'
                    : scan.state === 'failed'
                      ? 'red'
                      : scan.state === 'running'
                        ? 'orange'
                        : 'gray'
                }
                dot
              >
                {scan.state.toUpperCase()}
              </Badge>
            </div>
            <h1 className="text-2xl font-display font-bold text-white tracking-tight">
              Target: <span className="font-mono text-acc">{scan.target}</span>
            </h1>
            <div className="mt-1 flex items-center gap-3 text-xs text-text-muted font-mono">
              <span className="flex items-center gap-1">
                <Clock size={12} />
                {new Date(scan.created_at).toLocaleTimeString()}
              </span>
              {scan.finished_at && (
                <span>Finished {new Date(scan.finished_at).toLocaleTimeString()}</span>
              )}
            </div>
          </div>

          {!isTerminal && (
            <div className="flex items-center gap-2 rounded-lg bg-prime-900 border border-border px-3 py-1.5">
              <RefreshCw size={14} className="animate-spin text-acc" />
              <span className="font-mono text-xs text-acc">Auto-refreshing</span>
            </div>
          )}
        </div>

        {/* KPI stat grid */}
        <div className="grid grid-cols-3 gap-3 border-t border-border pt-6">
          <div className="rounded-xl bg-prime-900/60 border border-border p-4 text-center">
            <MetricStat value={scan.host_count} label="Discovered Hosts" valueClassName="!text-3xl" className="items-center" />
          </div>
          <div className="rounded-xl bg-prime-900/60 border border-border p-4 text-center">
            <MetricStat
              value={scan.vulnerability_count}
              label="CVEs Matched"
              valueClassName={`!text-3xl ${scan.vulnerability_count > 0 ? 'text-acc-warm' : 'text-white'}`}
              className="items-center"
            />
          </div>
          <div className="rounded-xl bg-prime-900/60 border border-border p-4 text-center">
            <MetricStat
              value={durationSec != null ? `${durationSec}s` : scan.started_at ? 'Scanning…' : '—'}
              label="Execution Time"
              valueClassName="!text-3xl"
              className="items-center"
            />
          </div>
        </div>

        {scan.state === 'failed' && scan.error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 font-mono text-xs text-red-400">
            Error: {scan.error}
          </div>
        )}

        {scan.state === 'completed' && scan.host_count === 0 && (
          <div className="rounded-lg border border-border bg-prime-900/60 p-4 font-mono text-xs text-text-secondary">
            Scan completed with 0 responsive hosts. Target may be filtering probes or hosts are offline.
          </div>
        )}
      </PrimeCard>

      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-base font-display font-semibold text-white tracking-tight">Discovered Ports &amp; CVE Footprint</h2>
        </div>
        <HostTable hosts={scan.hosts} scanId={scan.id} />
      </section>
    </div>
  )
}

export default ScanDetailView
