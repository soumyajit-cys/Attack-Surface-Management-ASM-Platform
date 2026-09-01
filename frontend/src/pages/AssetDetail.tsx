import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useToast } from '../components/ui/Toaster'
import { api, getApiErrorMessage } from '../lib/api'
import type { AssetGraphData } from '../AssetGraph'
import { ArrowLeft, Loader2, RefreshCw } from 'lucide-react'
import { AssetGraph } from '../AssetGraph'

interface AssetDetailData {
  id: number
  name: string
  criticality: string
  exposure: string | null
  created_at: string
  updated_at: string
  risk_score: number
  domains_count: number
  findings_count: number
  open_ports: number
  domains: Array<{
    id: number
    domain: string
    registrar: string
    asn: string
    subdomains: Array<{
      id: number
      subdomain: string
      ip_address: string
      source: string
      ports: Array<{
        id: number
        port: number
        protocol: string
        service: string
        status: string
        banner: string
      }>
      ssl: {
        issuer: string
        tls_version: string
        cipher: string
        expires_at: string
        self_signed: boolean
        risk_level: string
      } | null
    }>
  }>
}

export function AssetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { addToast } = useToast()
  const [asset, setAsset] = useState<AssetDetailData | null>(null)
  const [loading, setLoading] = useState(true)
  const [graphData, setGraphData] = useState<AssetGraphData | null>(null)
  const [graphLoading, setGraphLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('Info')

  const fetchAsset = async () => {
    if (!id) return
    setLoading(true)
    try {
      const data = await api.getAsset(Number(id))
      setAsset(data)
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to load asset', message: error.message })
    } finally {
      setLoading(false)
    }
  }

  const fetchGraph = async () => {
    if (!id) return
    setGraphLoading(true)
    try {
      const data = await api.getAssetGraph(Number(id))
      setGraphData(data)
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to load graph', message: error.message })
    } finally {
      setGraphLoading(false)
    }
  }

  useEffect(() => {
    fetchAsset()
    fetchGraph()
  }, [id])

  const getCriticalityColor = (c: string) => {
    switch (c) {
      case 'prod': return 'badge-critical'
      case 'staging': return 'badge-high'
      case 'dev': return 'badge-info'
      default: return 'badge-low'
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-600 border-t-transparent" />
      </div>
    )
  }
  if (!asset) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold text-gray-900">Asset not found</h2>
        <button onClick={() => navigate('/assets')} className="btn-primary mt-4">Back to Assets</button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate('/assets')} className="p-2 rounded-lg hover:bg-gray-100">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-gray-900">{asset.name}</h1>
              <span className={`badge ${getCriticalityColor(asset.criticality)}`}>
                {asset.criticality.charAt(0).toUpperCase() + asset.criticality.slice(1)}
              </span>
            </div>
            <p className="text-gray-500 mt-1">Created {new Date(asset.created_at).toLocaleDateString()}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary flex items-center gap-2" onClick={fetchAsset} disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="card p-6">
          <p className="text-sm text-gray-500">Risk Score</p>
          {asset.risk_score > 0 ? (
            <p className="text-3xl font-bold text-gray-900 mt-1">{asset.risk_score.toFixed(0)}</p>
          ) : (
            <p className="text-3xl font-bold text-gray-400 mt-1">—</p>
          )}
          <p className="text-sm text-gray-500 mt-1">{asset.risk_score > 0 ? '/10' : 'No score yet'}</p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">Domains</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">{asset.domains_count}</p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">Findings</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">{asset.findings_count}</p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">Subdomains</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">
            {asset.domains.reduce((acc, d) => acc + d.subdomains.length, 0)}
          </p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">Open Ports</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">{asset.open_ports}</p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">SSL Certificates</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">
            {asset.domains.reduce((acc, d) => acc + d.subdomains.filter(sub => sub.ssl).length, 0)}
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="card">
        <div className="border-b border-gray-200">
          <div className="flex gap-1 px-6" role="tablist">
            {['Info', 'Graph'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-4 border-b-2 font-medium text-sm ${
                  activeTab === tab
                    ? 'border-primary-600 text-primary-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        {activeTab === 'Graph' ? (
          <div className="p-6 overflow-x-auto">
            {graphLoading ? (
              <div className="flex items-center justify-center h-96">
                <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
              </div>
            ) : (
              <AssetGraph data={graphData} width={900} height={600} />
            )}
          </div>
        ) : (
        <div className="p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Domains & Subdomains</h2>
          {asset.domains.map((domain) => (
            <div key={domain.id} className="mb-6">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="font-semibold text-gray-900">{domain.domain}</h3>
                  <div className="flex items-center gap-2 text-sm text-gray-500 mt-1">
                    {domain.registrar && <span>Registrar: {domain.registrar}</span>}
                    {domain.asn && <span>ASN: {domain.asn}</span>}
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                {domain.subdomains.map((sub) => (
                  <div key={sub.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex flex-wrap items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <span className="font-mono font-medium text-gray-900">{sub.subdomain}</span>
                        {sub.ip_address && <span className="text-sm text-gray-500">{sub.ip_address}</span>}
                        <span className={`badge ${sub.source === 'primary' ? 'badge-critical' : 'badge-info'}`}>{sub.source}</span>
                      </div>
                      <div className="flex items-center gap-4">
                        {sub.ports.map((port) => (
                          <span key={port.id} className={`badge ${port.status === 'open' ? 'badge-critical' : 'badge-low'}`}>
                            {port.port}/{port.protocol} {port.service}
                          </span>
                        ))}
                        {sub.ssl && (
                          <span className={`badge ${sub.ssl.risk_level === 'critical' ? 'badge-critical' : sub.ssl.risk_level === 'high' ? 'badge-high' : sub.ssl.risk_level === 'medium' ? 'badge-medium' : 'badge-low'}`}>
                            SSL: {sub.ssl.tls_version} ({sub.ssl.risk_level})
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        )}
      </div>
    </div>
  )
}