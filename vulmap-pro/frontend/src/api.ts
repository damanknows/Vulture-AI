/**
 * Thin API client. During Vite dev, requests to `/api/*` are proxied to
 * http://127.0.0.1:8000 (see vite.config.ts). In production the frontend
 * can be served behind the same origin.
 */

export type ScanState = 'queued' | 'running' | 'completed' | 'failed'

export interface Port {
  id: number
  number: number
  protocol: string
  state: string
  service_name?: string | null
  service_product?: string | null
  service_version?: string | null
  service_extra?: string | null
}

export interface Vulnerability {
  id: number
  cve_id: string
  description?: string | null
  cvss_v3_score?: number | null
  severity?: string | null
  published?: string | null
  matched_cpe?: string | null
}

export interface Host {
  id: number
  ip: string
  hostname?: string | null
  state: string
  ports: Port[]
}

export interface ScanSummary {
  id: number
  target: string
  state: ScanState
  created_at: string
  started_at?: string | null
  finished_at?: string | null
  host_count: number
  vulnerability_count: number
}

export interface ScanDetail extends ScanSummary {
  error?: string | null
  hosts: Host[]
}

const BASE = '/api'

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    headers: { 'content-type': 'application/json' },
    ...init,
  })
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`
    try {
      const body = await resp.json()
      detail = body.detail ?? detail
    } catch {
      /* not json */
    }
    throw new Error(detail)
  }
  return (await resp.json()) as T
}

export const api = {
  listScans: () => jsonFetch<ScanSummary[]>('/scans'),
  getScan: (id: number) => jsonFetch<ScanDetail>(`/scans/${id}`),
  createScan: (target: string) =>
    jsonFetch<ScanSummary>('/scans', {
      method: 'POST',
      body: JSON.stringify({ target }),
    }),
  listVulnerabilities: (scanId: number) =>
    jsonFetch<Vulnerability[]>(`/hosts/vulnerabilities?scan_id=${scanId}`),
  health: () => jsonFetch<{ status: string }>('/health'),
}
