import React, { useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { FileText, Download, FileSpreadsheet, File, Loader2, Calendar, Filter, Save } from 'lucide-react'

export function Reports() {
  const { addToast } = useToast()
  const [exporting, setExporting] = useState<string | null>(null)
  const [pdfAssetId, setPdfAssetId] = useState<string>('')
  const [pdfLoading, setPdfLoading] = useState(false)
  const [dateRange, setDateRange] = useState({ start: '', end: '' })
  const [severityFilter, setSeverityFilter] = useState('')

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)
  }

  const handleExportFindings = async () => {
    setExporting('findings')
    try {
      const blob = await api.exportFindingsCsv({ since: dateRange.start || undefined, severity: severityFilter || undefined })
      downloadBlob(blob, `findings_${new Date().toISOString().split('T')[0]}.csv`)
      addToast({ type: 'success', title: 'Export complete', message: 'Findings CSV downloaded' })
    } catch (error) {
      addToast({ type: 'error', title: 'Export failed' })
    } finally {
      setExporting(null)
    }
  }

  const handleExportAssets = async () => {
    setExporting('assets')
    try {
      const blob = await api.exportAssetsCsv()
      downloadBlob(blob, `assets_${new Date().toISOString().split('T')[0]}.csv`)
      addToast({ type: 'success', title: 'Export complete', message: 'Assets CSV downloaded' })
    } catch (error) {
      addToast({ type: 'error', title: 'Export failed' })
    } finally {
      setExporting(null)
    }
  }

  const handleExportScans = async () => {
    setExporting('scans')
    try {
      const blob = await api.exportScansCsv({ since: dateRange.start || undefined })
      downloadBlob(blob, `scans_${new Date().toISOString().split('T')[0]}.csv`)
      addToast({ type: 'success', title: 'Export complete', message: 'Scans CSV downloaded' })
    } catch (error) {
      addToast({ type: 'error', title: 'Export failed' })
    } finally {
      setExporting(null)
    }
  }

  const handleExportDomains = async () => {
    setExporting('domains')
    try {
      const blob = await api.exportDomainsCsv()
      downloadBlob(blob, `domains_${new Date().toISOString().split('T')[0]}.csv`)
      addToast({ type: 'success', title: 'Export complete', message: 'Domains CSV downloaded' })
    } catch (error) {
      addToast({ type: 'error', title: 'Export failed' })
    } finally {
      setExporting(null)
    }
  }

  const handleExportAll = async () => {
    setExporting('all')
    try {
      const blob = await api.exportAllCsv()
      downloadBlob(blob, `sentinelasm_export_${new Date().toISOString().split('T')[0]}.zip`)
      addToast({ type: 'success', title: 'Export complete', message: 'Full export downloaded' })
    } catch (error) {
      addToast({ type: 'error', title: 'Export failed' })
    } finally {
      setExporting(null)
    }
  }

  const handleGeneratePdf = async (assetId?: string) => {
    setPdfLoading(true)
    try {
      const blob = await api.getExecutiveSummaryPdf(assetId || undefined)
      downloadBlob(blob, `executive_summary_${new Date().toISOString().split('T')[0]}.pdf`)
      addToast({ type: 'success', title: 'PDF generated', message: 'Executive summary downloaded' })
    } catch (error: any) {
      if (error.message?.includes('fpdf2')) {
        addToast({ type: 'error', title: 'PDF unavailable', message: 'PDF generation requires fpdf2 to be installed on the backend' })
      } else {
        addToast({ type: 'error', title: 'Generation failed', message: error.message })
      }
    } finally {
      setPdfLoading(false)
    }
  }

  const exportItems = [
    { key: 'findings', label: 'Findings', icon: AlertTriangle, description: 'All security findings with filters', action: handleExportFindings, loading: exporting === 'findings' },
    { key: 'assets', label: 'Assets', icon: Server, description: 'Asset inventory with risk scores', action: handleExportAssets, loading: exporting === 'assets' },
    { key: 'scans', label: 'Scans', icon: Scan, description: 'Scan history and results', action: handleExportScans, loading: exporting === 'scans' },
    { key: 'domains', label: 'Domains', icon: Globe, description: 'Domain and subdomain inventory', action: handleExportDomains, loading: exporting === 'domains' },
    { key: 'all', label: 'Complete Export (ZIP)', icon: FileSpreadsheet, description: 'All data in a single ZIP archive', action: handleExportAll, loading: exporting === 'all' },
  ]

  const pdfItems = [
    { key: 'executive', label: 'Executive Summary', description: 'Risk posture overview with top findings and recommendations', action: () => handleGeneratePdf(), loading: pdfLoading },
    { key: 'asset', label: 'Asset-Specific Report', description: 'Detailed report for a specific asset (enter Asset ID)', action: () => handleGeneratePdf(pdfAssetId), loading: pdfLoading },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Reports & Exports</h1>
          <p className="text-gray-600">Generate and download reports in various formats</p>
        </div>
      </div>

      {/* CSV Exports */}
      <div className="card">
        <div className="p-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">CSV Exports</h2>
        </div>
        <div className="p-4 border-b border-gray-200">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <label className="label">Start Date</label>
              <input type="date" className="input" value={dateRange.start} onChange={(e) => setDateRange({...dateRange, start: e.target.value})} />
            </div>
            <div className="flex-1">
              <label className="label">End Date</label>
              <input type="date" className="input" value={dateRange.end} onChange={(e) => setDateRange({...dateRange, end: e.target.value})} />
            </div>
            <div className="flex-1">
              <label className="label">Severity Filter</label>
              <select className="input" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>
        </div>
        <div className="p-4 divide-y divide-gray-200">
          {exportItems.map((item) => (
            <div key={item.key} className="flex items-center justify-between p-4 hover:bg-gray-50">
              <div className="flex items-center gap-4">
                <div className="p-2 bg-gray-100 rounded-lg">
                  <item.icon className="w-5 h-5 text-gray-600" />
                </div>
                <div>
                  <p className="font-medium text-gray-900">{item.label}</p>
                  <p className="text-sm text-gray-500">{item.description}</p>
                </div>
              </div>
              <button
                onClick={item.action}
                disabled={item.loading}
                className="btn-secondary flex items-center gap-2"
              >
                <FileSpreadsheet className="w-4 h-4" />
                {item.loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Export'}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* PDF Reports */}
      <div className="card mt-6">
        <div className="p-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">PDF Reports</h2>
        </div>
        <div className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {pdfItems.map((item) => (
              <div key={item.key} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <p className="font-medium text-gray-900">{item.label}</p>
                    <p className="text-sm text-gray-500 mt-1">{item.description}</p>
                    {item.key === 'asset' && (
                      <div className="mt-3">
                        <label className="label">Asset ID</label>
                        <input
                          type="number"
                          className="input"
                          placeholder="Enter Asset ID"
                          value={pdfAssetId}
                          onChange={(e) => setPdfAssetId(e.target.value)}
                        />
                      </div>
                    )}
                  </div>
                  <button
                    onClick={item.action}
                    disabled={item.loading || (item.key === 'asset' && !pdfAssetId)}
                    className="btn-primary flex items-center gap-2 whitespace-nowrap"
                  >
                    <FileText className="w-4 h-4" />
                    {item.loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Generate PDF'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}