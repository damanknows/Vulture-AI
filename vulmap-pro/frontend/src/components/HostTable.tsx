import { useEffect, useState } from 'react'
import { api, type Host, type Vulnerability } from '../api'
import { SeverityBadge } from './SeverityBadge'
import { Badge, PrimeCard } from './ui'

interface Props {
  hosts: Host[]
  scanId: number
}

export function HostTable({ hosts, scanId }: Props) {
  const [cvesByPort, setCvesByPort] = useState<Record<number, Vulnerability[]>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api
      .listVulnerabilities(scanId)
      .then((rows) => {
        if (cancelled) return
        const grouped: Record<number, Vulnerability[]> = {}
        for (const v of rows) {
          grouped[0] = [...(grouped[0] ?? []), v]
        }
        setCvesByPort(grouped)
      })
      .catch((err) => !cancelled && setError(err.message ?? 'failed to load CVEs'))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [scanId])

  if (hosts.length === 0) {
    return (
      <PrimeCard className="text-center p-8 font-mono text-xs text-text-muted">
        No hosts were discovered for this scan. The target may have been unreachable or firewalled.
      </PrimeCard>
    )
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 font-mono text-xs text-amber-300">
          Could not load CVE details: {error}
        </div>
      )}
      {hosts.map((h) => (
        <PrimeCard key={h.id} noPadding className="overflow-hidden border border-border">
          <div className="flex items-center justify-between border-b border-border bg-prime-900/80 px-4 py-3">
            <div className="flex items-center gap-3">
              <span className="font-mono text-sm font-semibold text-acc">{h.ip}</span>
              {h.hostname && (
                <span className="font-mono text-xs text-text-secondary bg-prime-700/50 px-2 py-0.5 rounded border border-border">
                  {h.hostname}
                </span>
              )}
            </div>
            <Badge variant={h.state === 'up' ? 'cyan' : 'gray'} dot size="xs">
              {h.state.toUpperCase()}
            </Badge>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-prime-900/40 font-mono uppercase text-text-muted border-b border-border text-[10px]">
                <tr>
                  <th className="px-4 py-2.5">Port</th>
                  <th className="px-4 py-2.5">State</th>
                  <th className="px-4 py-2.5">Service</th>
                  <th className="px-4 py-2.5">Product &amp; Version</th>
                  <th className="px-4 py-2.5">Matched CVEs</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {h.ports.map((p) => (
                  <tr key={p.id} className="transition-colors hover:bg-prime-700/30 font-mono">
                    <td className="px-4 py-2.5 text-text-primary font-bold">
                      {p.number}/{p.protocol}
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge variant={p.state === 'open' ? 'cyan' : 'gray'} dot={false} size="xs">
                        {p.state}
                      </Badge>
                    </td>
                    <td className="px-4 py-2.5 text-acc-warm font-medium">{p.service_name ?? '—'}</td>
                    <td className="px-4 py-2.5 text-text-secondary">
                      {[p.service_product, p.service_version, p.service_extra]
                        .filter(Boolean)
                        .join(' ') || '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      <PortCves portId={p.id} cves={cvesByPort[p.id] ?? []} loading={loading} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </PrimeCard>
      ))}
    </div>
  )
}

function PortCves({ portId, cves, loading }: { portId: number; cves: Vulnerability[]; loading: boolean }) {
  if (loading) return <span className="font-mono text-[10px] text-text-muted animate-pulse">Querying NVD…</span>
  if (!cves.length)
    return <span className="font-mono text-[10px] text-text-muted">0 CVEs detected</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {cves.map((c) => (
        <span key={`${portId}-${c.id}`} className="inline-flex items-center gap-1.5 bg-prime-900 border border-border px-2 py-0.5 rounded">
          <SeverityBadge severity={c.severity} score={c.cvss_v3_score} />
          <a
            className="font-mono text-[11px] text-acc hover:underline"
            href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
            target="_blank"
            rel="noreferrer"
          >
            {c.cve_id}
          </a>
        </span>
      ))}
    </div>
  )
}

export default HostTable
