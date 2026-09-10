import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { PrimeCard, PrimeButton, PrimeInput, Badge } from './ui'
import { Shield, ArrowRight } from 'lucide-react'

interface Props {
  onScanQueued?: () => void
}

/**
 * Top-level summary: aggregated counters plus a "Start a scan" form.
 * Uses a single in-flight request to validate the target before queuing.
 */
export function Dashboard({ onScanQueued }: Props) {
  const [target, setTarget] = useState('127.0.0.1')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const scan = await api.createScan(target.trim())
      onScanQueued?.()
      navigate(`/scans/${scan.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to start scan')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-6">
      <PrimeCard variant="accent" className="relative overflow-hidden">
        <div className="flex items-center gap-2 mb-2">
          <Badge variant="cyan" dot>TARGET ACQUISITION</Badge>
        </div>
        <h2 className="text-xl font-display font-bold text-white tracking-tight">Launch Vulnerability Scan</h2>
        <p className="mt-1 text-sm text-text-secondary">
          Target IPs or hostnames are validated against an allowlist (loopback &amp; RFC1918 by
          default; configure via <code className="font-mono text-xs text-acc">ALLOWED_TARGETS</code>).
        </p>

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col sm:flex-row gap-3 items-start sm:items-end">
          <div className="flex-1 w-full">
            <PrimeInput
              label="Target IP / Hostname"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="127.0.0.1 or 192.168.1.0/24"
              leadingIcon={<Shield size={16} />}
              spellCheck={false}
              required
            />
          </div>
          <PrimeButton
            type="submit"
            variant="primary"
            size="md"
            loading={submitting}
            disabled={!target.trim()}
            icon={<ArrowRight size={16} />}
            className="w-full sm:w-auto shrink-0"
          >
            {submitting ? 'Queuing…' : 'Start Scan'}
          </PrimeButton>
        </form>

        {error && (
          <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 font-mono text-xs text-red-400">
            {error}
          </div>
        )}
      </PrimeCard>

      <PrimeCard variant="default">
        <h2 className="text-base font-semibold text-white tracking-tight">Automated Analysis Pipeline</h2>
        <ol className="mt-3 space-y-2 text-sm text-text-secondary list-none">
          <li className="flex items-start gap-2.5">
            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-acc/10 font-mono text-xs font-semibold text-acc">
              1
            </span>
            <span>Target CIDR &amp; hostname resolution with allowlist enforcement.</span>
          </li>
          <li className="flex items-start gap-2.5">
            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-acc/10 font-mono text-xs font-semibold text-acc">
              2
            </span>
            <span>Nmap service fingerprinting probe (<code className="font-mono text-xs text-acc">-sV</code>) runs concurrently.</span>
          </li>
          <li className="flex items-start gap-2.5">
            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-acc/10 font-mono text-xs font-semibold text-acc">
              3
            </span>
            <span>Detected CPEs matched against NIST NVD CVE repository with CVSS v3 scoring.</span>
          </li>
          <li className="flex items-start gap-2.5">
            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-acc/10 font-mono text-xs font-semibold text-acc">
              4
            </span>
            <span>Results indexed in real-time SQLite vulnerability database with caching.</span>
          </li>
        </ol>
      </PrimeCard>
    </div>
  )
}

export default Dashboard
