import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useToast } from '../components/ui/Toaster'
import { api, getApiErrorMessage } from '../lib/api'
import type { DashboardData, Scan } from '../lib/types'
import {
  Server,
  AlertTriangle,
  Scan as ScanIcon,
  Clock,
  RefreshCw,
  CheckCircle,
  AlertCircle,
} from 'lucide-react'
import {
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'

interface FindingSeverity {
  severity: string
  count: number
  color: string
}

export function Dashboard() {
  const navigate = useNavigate()
  const { addToast } = useToast()
  const [data, setData] = useState<DashboardData | null>(null)
  const [recentScans, setRecentScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const fetchDashboard = async () => {
    try {
      const dashData = await api.getDashboard()
      setData(dashData)
      const scansData = await api.getScans({ page: 1, page_size: 5 })
      setRecentScans(scansData.items)
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to load dashboard', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => { fetchDashboard() }, [])

  const handleRefresh = async () => {
    setRefreshing(true)
    await fetchDashboard()
  }

  const severityData: FindingSeverity[] = data
    ? [
        { severity: 'Critical', count: data.critical, color: '#dc2626' },
        { severity: 'High', count: data.high, color: '#ea580c' },
        { severity: 'Medium', count: data.medium, color: '#f59e0b' },
        { severity: 'Low', count: data.low, color: '#3b82f6' },
        { severity: 'Info', count: data.info, color: '#6b7280' },
      ]
    : []

  const stats = [
    { label: 'Total Assets', value: data?.assets ?? 0, icon: Server, color: 'bg-primary-100 text-primary-600' },
    { label: 'Total Findings', value: data?.findings ?? 0, icon: AlertTriangle, color: 'bg-danger-100 text-danger-600' },
    { label: 'Critical', value: data?.critical ?? 0, icon: AlertTriangle, color: 'bg-danger-100 text-danger-600' },
    { label: 'Scans Completed', value: data?.scans_completed ?? 0, icon: ScanIcon, color: 'bg-success-100 text-success-600' },
  ]

  const getScanStatusProps = (status: string) => {
    switch (status) {
      case 'completed': return { color: 'bg-green-100', iconColor: 'text-green-600', Icon: CheckCircle, label: 'Completed' }
      case 'running': return { color: 'bg-blue-100', iconColor: 'text-blue-600', Icon: Clock, label: 'Running' }
      case 'pending': return { color: 'bg-yellow-100', iconColor: 'text-yellow-600', Icon: Clock, label: 'Pending' }
      case 'failed': return { color: 'bg-red-100', iconColor: 'text-red-600', Icon: AlertCircle, label: 'Failed' }
      default: return { color: 'bg-gray-100', iconColor: 'text-gray-600', Icon: AlertCircle, label: status }
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-600 border-t-transparent" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-600">Overview of your attack surface posture</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="btn-secondary flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <div key={stat.label} className="card p-6">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm text-gray-500">{stat.label}</p>
                <p className="text-3xl font-bold text-gray-900 mt-1">{stat.value}</p>
              </div>
              <div className={`p-3 rounded-xl ${stat.color}`}>
                <stat.icon className="w-6 h-6" />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Findings by Severity</h3>
          <div className="h-64 flex items-center justify-center">
            {data?.findings && data.findings > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData.filter((s) => s.count > 0)}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="count"
                    nameKey="severity"
                    label={({ severity, count, percent }) => `${severity}: ${count} (${(percent * 100).toFixed(0)}%)`}
                    labelLine={false}
                  >
                    {severityData.filter((s) => s.count > 0).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value: number) => [value, 'findings']} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="w-full h-full flex items-center justify-center text-gray-500">
                No findings data available
              </div>
            )}
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            {severityData.map((s) => (
              <div key={s.severity} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: s.color }} />
                <span className="text-sm text-gray-600">{s.severity}: {s.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Recent Scans</h3>
            <button onClick={() => navigate('/scans')} className="text-sm text-primary-600 hover:text-primary-700">View all</button>
          </div>
          <div className="space-y-3">
            {recentScans.length > 0 ? recentScans.map((scan) => {
              const props = getScanStatusProps(scan.status)
              return (
                <div key={scan.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg ${props.color} flex items-center justify-center`}>
                      <props.Icon className={`w-5 h-5 ${props.iconColor}`} />
                    </div>
                    <div>
                      <p className="font-medium text-gray-900">{scan.target}</p>
                      <p className="text-sm text-gray-500">{props.label}</p>
                    </div>
                  </div>
                  <div className="text-sm text-gray-500">
                    {scan.completed_at
                      ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)}s`
                      : scan.started_at
                        ? 'In progress'
                        : 'Queued'}
                  </div>
                </div>
              )
            }) : (
              <div className="text-center py-8 text-gray-500">
                No scans yet. <button onClick={() => navigate('/scans')} className="text-primary-600 hover:underline">Start one</button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
