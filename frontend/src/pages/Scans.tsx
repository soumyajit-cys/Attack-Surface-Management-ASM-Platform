import { useEffect, useState } from 'react'
import { useToast } from '../components/ui/Toaster'
import { api, getApiErrorMessage } from '../lib/api'
import { scanStatusBadgeClass, verificationBadgeClass } from '../lib/statusBadges'
import type { Scan, VerificationChallenge, VerifiedDomain } from '../lib/types'
import {
  Scan as ScanIcon,
  Loader2,
  Play,
  Clock,
  CheckCircle,
  AlertCircle,
  MinusCircle,
  ShieldCheck,
  Ban,
} from 'lucide-react'

const PAGE_SIZE = 50

export function Scans() {
  const { addToast } = useToast()
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [startingScan, setStartingScan] = useState(false)
  const [scanDomain, setScanDomain] = useState('')
  const [verifyDomain, setVerifyDomain] = useState('')
  const [verifyMethod, setVerifyMethod] = useState<'dns_txt' | 'http_file'>('dns_txt')
  const [challenge, setChallenge] = useState<VerificationChallenge | null>(null)
  const [requesting, setRequesting] = useState(false)
  const [checking, setChecking] = useState(false)
  const [verifiedDomains, setVerifiedDomains] = useState<VerifiedDomain[]>([])

  const fetchVerifiedDomains = async () => {
    try {
      const data = await api.listVerifiedDomains()
      setVerifiedDomains(data.items)
    } catch (error) {
      addToast({
        type: 'error',
        title: 'Failed to load verification status',
        message: getApiErrorMessage(error),
      })
    }
  }

  const fetchScans = async () => {
    setLoading(true)
    try {
      const data = await api.getScans({ page: 1, page_size: PAGE_SIZE })
      setScans(data.items)
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to load scans', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchScans()
    fetchVerifiedDomains()
  }, [])

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!scanDomain.trim()) return
    setStartingScan(true)
    try {
      await api.startScan(scanDomain)
      addToast({ type: 'success', title: 'Scan started', message: `Scanning ${scanDomain}` })
      setScanDomain('')
      fetchScans()
    } catch (error) {
      const message = getApiErrorMessage(error)
      if (message.toLowerCase().includes('not verified')) {
        setVerifyDomain(scanDomain.trim().toLowerCase())
        addToast({
          type: 'warning',
          title: 'Domain not verified',
          message: `${message} Verify ownership below, then retry the scan.`,
        })
      } else {
        addToast({ type: 'error', title: 'Failed to start scan', message })
      }
    } finally {
      setStartingScan(false)
    }
  }

  const handleRequestChallenge = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!verifyDomain.trim()) return
    setRequesting(true)
    try {
      const data = await api.requestVerification(verifyDomain.trim(), verifyMethod)
      setChallenge(data)
      addToast({ type: 'info', title: 'Challenge issued', message: data.instructions })
    } catch (error) {
      addToast({ type: 'error', title: 'Challenge failed', message: getApiErrorMessage(error) })
    } finally {
      setRequesting(false)
    }
  }

  const handleCheckNow = async () => {
    const domain = challenge?.domain ?? verifyDomain.trim()
    if (!domain) return
    setChecking(true)
    try {
      const result = await api.checkVerification(domain)
      addToast({ type: 'success', title: 'Domain verified', message: result.message })
      setChallenge(null)
      fetchVerifiedDomains()
    } catch (error) {
      addToast({ type: 'error', title: 'Not verified yet', message: getApiErrorMessage(error) })
    } finally {
      setChecking(false)
    }
  }

  const getVerificationBadge = (status: string) => verificationBadgeClass(status)

  const getStatusColor = (status: string) => scanStatusBadgeClass(status)

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-4 h-4" />
      case 'running':
        return <Loader2 className="w-4 h-4 animate-spin" />
      case 'pending':
        return <Clock className="w-4 h-4" />
      case 'failed':
        return <AlertCircle className="w-4 h-4" />
      case 'skipped':
        // Phase 1: gated by domain verification — see the error column.
        return <Ban className="w-4 h-4" />
      default:
        return <MinusCircle className="w-4 h-4" />
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scans</h1>
          <p className="text-gray-600">Manage and monitor your scans</p>
        </div>
      </div>

      <div className="card">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5" />
            Domain verification
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Scans require proof of ownership. Verify a domain (or its parent) once — subdomains are
            covered automatically.
          </p>
          <form onSubmit={handleRequestChallenge} className="flex flex-col sm:flex-row gap-4 mt-4">
            <input
              type="text"
              value={verifyDomain}
              onChange={(e) => setVerifyDomain(e.target.value)}
              className="input flex-1"
              placeholder="example.com"
              required
            />
            <select
              value={verifyMethod}
              onChange={(e) => setVerifyMethod(e.target.value as 'dns_txt' | 'http_file')}
              className="input"
            >
              <option value="dns_txt">DNS TXT record</option>
              <option value="http_file">HTTP file</option>
            </select>
            <button type="submit" className="btn-secondary" disabled={requesting}>
              {requesting ? 'Issuing…' : 'Get challenge'}
            </button>
          </form>
          {challenge && (
            <div className="mt-4 p-4 bg-gray-50 rounded text-sm space-y-2">
              <p className="text-gray-700">{challenge.instructions}</p>
              {challenge.txt_record_name && (
                <p className="font-mono break-all">
                  {challenge.txt_record_name} → {challenge.expected_txt_value}
                </p>
              )}
              {challenge.file_path && (
                <p className="font-mono break-all">
                  {challenge.file_path} → {challenge.file_content}
                </p>
              )}
              <button onClick={handleCheckNow} className="btn-primary" disabled={checking}>
                {checking ? 'Checking…' : 'Check now'}
              </button>
            </div>
          )}
        </div>
        <div className="p-6">
          <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wider mb-2">
            Verification status
          </h3>
          {verifiedDomains.length === 0 && (
            <p className="text-sm text-gray-500">No domains verified yet.</p>
          )}
          <ul className="space-y-2">
            {verifiedDomains.map((v) => (
              <li key={v.domain} className="flex items-center gap-2 text-sm flex-wrap">
                <span className="font-medium text-gray-900">{v.domain}</span>
                <span className={`badge ${getVerificationBadge(v.status)}`}>{v.status}</span>
                {v.status === 'grandfathered' && v.expires_at && (
                  <span className="text-amber-700">
                    grace expires {new Date(v.expires_at).toLocaleDateString()} — verify to keep
                    scanning
                  </span>
                )}
                {v.status === 'verified' && v.expires_at && (
                  <span className="text-gray-500">
                    expires {new Date(v.expires_at).toLocaleDateString()}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="card">
        <div className="p-6 border-b border-gray-200">
          <form onSubmit={handleStartScan} className="flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1">
              <ScanIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={scanDomain}
                onChange={(e) => setScanDomain(e.target.value)}
                className="input pl-10"
                placeholder="Enter domain to scan"
                required
              />
            </div>
            <button
              type="submit"
              className="btn-primary flex items-center gap-2"
              disabled={startingScan}
            >
              <Play className="w-4 h-4" />
              Start Scan
            </button>
          </form>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Target
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Started
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Completed
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Duration
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Error
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {loading && (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-gray-500">
                    <Loader2 className="w-6 h-6 animate-spin inline-block text-primary-600" />
                  </td>
                </tr>
              )}
              {!loading && scans.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-gray-500">
                    No scans found. Start a scan to begin.
                  </td>
                </tr>
              )}
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-gray-50">
                  <td className="px-4 py-4 font-medium text-gray-900">{scan.target}</td>
                  <td className="px-4 py-4">
                    <span
                      className={`flex items-center gap-1 badge ${getStatusColor(scan.status)}`}
                    >
                      {getStatusIcon(scan.status)}
                      {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-gray-500">
                    {new Date(scan.started_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-4 text-gray-500">
                    {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '-'}
                  </td>
                  <td className="px-4 py-4 text-gray-500">
                    {scan.completed_at
                      ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)}s`
                      : '-'}
                  </td>
                  <td className="px-4 py-4 text-gray-500 max-w-xs truncate">{scan.error || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
