import React, { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { Scan, Loader2, Plus, Play, RefreshCw, Clock, CheckCircle, AlertCircle, MinusCircle } from 'lucide-react'

interface Scan {
  id: number
  target: string
  status: string
  error: string | null
  started_at: string
  completed_at: string | null
}

export function Scans() {
  const { addToast } = useToast()
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [startingScan, setStartingScan] = useState(false)
  const [scanDomain, setScanDomain] = useState('')

  const fetchScans = async () => {
    setLoading(true)
    try {
      const data = await api.getScans({ page: 1, page_size: 50 })
      setScans(data.items)
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to load scans', message: error.message })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchScans() }, [])

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!scanDomain.trim()) return
    setStartingScan(true)
    try {
      await api.startScan(scanDomain)
      addToast({ type: 'success', title: 'Scan started', message: `Scanning ${scanDomain}` })
      setScanDomain('')
      fetchScans()
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to start scan', message: error.message })
    } finally {
      setStartingScan(false)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-success-600 bg-success-100'
      case 'running': return 'text-primary-600 bg-primary-100'
      case 'pending': return 'text-warning-600 bg-warning-100'
      case 'failed': return 'text-danger-600 bg-danger-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4" />
      case 'running': return <Loader2 className="w-4 h-4 animate-spin" />
      case 'pending': return <Clock className="w-4 h-4" />
      case 'failed': return <AlertCircle className="w-4 h-4" />
      default: return <MinusCircle className="w-4 h-4" />
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
          <form onSubmit={handleStartScan} className="flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1">
              <Scan className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
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
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Started</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Completed</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Duration</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-gray-50">
                  <td className="px-4 py-4 font-medium text-gray-900">{scan.target}</td>
                  <td className="px-4 py-4">
                    <span className={`flex items-center gap-1 badge ${getStatusColor(scan.status)}`}>
                      {getStatusIcon(scan.status)}
                      {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-gray-500">{new Date(scan.started_at).toLocaleString()}</td>
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