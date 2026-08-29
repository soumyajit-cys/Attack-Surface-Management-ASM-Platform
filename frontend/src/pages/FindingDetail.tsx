import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { ArrowLeft, AlertTriangle, AlertCircle, MinusCircle, Info } from 'lucide-react'

interface FindingDetailData {
  id: number
  asset_id: number
  asset_name?: string | null
  title: string
  severity: string
  category: string
  description: string
  recommendation: string
  created_at: string
}

export function FindingDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { addToast } = useToast()
  const [finding, setFinding] = useState<FindingDetailData | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchFinding = async () => {
    if (!id) return
    setLoading(true)
    try {
      const data = await api.getFinding(Number(id))
      setFinding(data)
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to load finding', message: error.message })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchFinding() }, [id])

  const severityColors = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-600 border-t-transparent" />
      </div>
    )
  }
  if (!finding) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold text-gray-900">Finding not found</h2>
        <button onClick={() => navigate('/findings')} className="btn-primary mt-4">Back to Findings</button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate('/findings')} className="p-2 rounded-lg hover:bg-gray-100">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{finding.title}</h1>
            <div className="flex items-center gap-2 mt-1">
              <span className={`badge ${severityColors[finding.severity as keyof typeof severityColors] || 'badge-info'}`}>
                {finding.severity.toUpperCase()}
              </span>
              <span className="text-sm text-gray-500 capitalize">{finding.category.replace('_', ' ')}</span>
            </div>
            <p className="text-gray-500 mt-1">Created {new Date(finding.created_at).toLocaleString()}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="card p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Description</h2>
            <p className="text-gray-600 whitespace-pre-wrap">{finding.description}</p>
          </div>

          <div className="card p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Recommendation</h2>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-gray-700">{finding.recommendation}</p>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="card p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Details</h2>
            <dl className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <dt className="text-sm text-gray-500">Asset ID</dt>
                  <dd className="font-medium text-gray-900">{finding.asset_id}</dd>
                </div>
                <div>
                  <dt className="text-sm text-gray-500">Severity</dt>
                  <dd className="font-medium text-gray-900">
                    <span className={`badge ${severityColors[finding.severity as keyof typeof severityColors] || 'badge-info'}`}>
                      {finding.severity.toUpperCase()}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt className="text-sm text-gray-500">Category</dt>
                  <dd className="font-medium text-gray-900 capitalize">{finding.category.replace('_', ' ')}</dd>
                </div>
                <div>
                  <dt className="text-sm text-gray-500">Created</dt>
                  <dd className="font-medium text-gray-900">{new Date(finding.created_at).toLocaleString()}</dd>
                </div>
              </div>
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}