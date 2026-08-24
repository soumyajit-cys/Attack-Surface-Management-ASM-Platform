import React, { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { Server, AlertTriangle, Scan, ExternalLink, ArrowLeft, Loader2, RefreshCw } from 'lucide-react'
import { AssetGraph } from '../components/AssetGraph'

interface AssetDetailData {
  id: number
  name: string
  criticality: string
  created_at: string
  updated_at: string
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
  const [graphData, setGraphData] = useState<any>(null)
  const [graphLoading, setGraphLoading] = useState(false)

  const fetchAsset = async () => {
    if (!id) return
    setLoading(true)
    try {
      // Mock data
      setAsset({
        id: 1,
        name: 'example.com',
        criticality: 'prod',
        created_at: '2024-01-15T10:00:00Z',
        updated_at: '2024-01-20T10:00:00Z',
        domains: [
          {
            id: 1,
            domain: 'example.com',
            registrar: 'RESERVED-Internet Assigned Numbers Authority',
            asn: 'AS15133',
            subdomains: [
              {
                id: 1,
                subdomain: 'example.com',
                ip_address: '93.184.216.34',
                source: 'primary',
                ports: [
                  { id: 1, port: 80, protocol: 'tcp', service: 'http', status: 'open', banner: 'nginx/1.18.0' },
                  { id: 2, port: 443, protocol: 'tcp', service: 'https', status: 'open', banner: 'nginx/1.18.0' },
                ],
                ssl: {
                  issuer: 'CN=Let\'s Encrypt R3',
                  tls_version: 'TLSv1.3',
                  cipher: 'TLS_AES_256_GCM_SHA384',
                  expires_at: '2024-07-15T12:00:00Z',
                  self_signed: false,
                  risk_level: 'low',
                },
              },
            ],
          },
        ],
      })
    } catch (error) {
      console.error('Failed to load asset:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchGraph = async () => {
    if (!id) return
    setGraphLoading(true)
    try {
      // Mock graph data
      setGraphData({
        asset_id: 1,
        nodes: [
          { id: 'asset-1', type: 'asset', label: 'example.com', data: { id: 1, name: 'example.com', criticality: 'prod' } },
          { id: 'domain-1', type: 'domain', label: 'example.com', data: { id: 1, domain: 'example.com', registrar: 'IANA', asn: 'AS15133' } },
          { id: 'subdomain-1', type: 'subdomain', label: 'example.com', data: { id: 1, subdomain: 'example.com', ip_address: '93.184.216.34', source: 'primary' } },
          { id: 'port-1', type: 'port', label: '80/tcp', data: { id: 1, port: 80, service: 'http', status: 'open' } },
          { id: 'port-2', type: 'port', label: '443/tcp', data: { id: 2, port: 443, service: 'https', status: 'open' } },
          { id: 'ssl-1', type: 'ssl', label: 'TLSv1.3', data: { issuer: 'Let\'s Encrypt R3', risk_level: 'low' } },
        ],
        edges: [
          { source: 'asset-1', target: 'domain-1', type: 'contains' },
          { source: 'domain-1', target: 'subdomain-1', type: 'resolves_to' },
          { source: 'subdomain-1', target: 'port-1', type: 'exposes' },
          { source: 'subdomain-1', target: 'port-2', type: 'exposes' },
          { source: 'subdomain-1', target: 'ssl-1', type: 'secured_by' },
        ],
      })
    } catch (error) {
      console.error('Failed to load graph:', error)
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

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-danger-600 bg-danger-100'
      case 'high': return 'text-danger-600 bg-danger-100'
      case 'medium': return 'text-warning-600 bg-warning-100'
      case 'low': return 'text-success-600 bg-success-100'
      default: return 'text-gray-600 bg-gray-100'
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
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card p-6">
          <p className="text-sm text-gray-500">Domains</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">{asset.domains.length}</p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">Subdomains</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">
            {asset.domains.reduce((acc, d) => acc + d.subdomains.length, 0)}
          </p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">Open Ports</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">
            {asset.domains.reduce((acc, d) => acc + d.subdomains.reduce((s, sub) => s + sub.ports.filter(p => p.status === 'open').length, 0), 0)}
          </p>
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
          <nav className="flex gap-8 px-6" aria-label="Tabs">
            <button className="py-4 px-1 border-b-2 border-primary-600 font-medium text-primary-600 text-sm">Overview</button>
            <button className="py-4 px-1 border-b-2 border-transparent font-medium text-gray-500 hover:text-gray-700 text-sm">Domains & Subdomains</button>
            <button className="py-4 px-1 border-b-2 border-transparent font-medium text-gray-500 hover:text-gray-700 text-sm">Ports & Services</button>
            <button className="py-4 px-1 border-b-2 border-transparent font-medium text-gray-500 hover:text-gray-700 text-sm">SSL/TLS</button>
            <button className="py-4 px-1 border-b-2 border-transparent font-medium text-gray-500 hover:text-gray-700 text-sm">Graph</button>
          </nav>
        </div>

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
      </div>
    </div>
  )
}