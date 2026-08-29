import { useEffect, useState } from 'react'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import {
  Server,
  AlertTriangle,
  Scan,
  FileText,
  Clock,
  Plus,
  RefreshCw,
  ArrowUpRight,
  ArrowDownRight,
  CheckCircle,
} from 'lucide-react'
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
} from 'recharts'

interface DashboardData {
  assets: number
  findings: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

interface RiskTrendPoint {
  date: string
  score: number
}

interface FindingSeverity {
  severity: string
  count: number
  color: string
}

export function Dashboard() {
  const { addToast } = useToast()
  const [data, setData] = useState<DashboardData | null>(null)
  const [riskTrend, setRiskTrend] = useState<RiskTrendPoint[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const fetchDashboard = async () => {
    try {
      const response = await api.getDashboard()
      setData(response.data)
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to load dashboard', message: 'Please try again' })
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  const fetchRiskTrend = async () => {
    try {
      // Mock data for now - in production this would come from an API endpoint
      const mockTrend: RiskTrendPoint[] = []
      for (let i = 29; i >= 0; i--) {
        const date = new Date()
        date.setDate(date.getDate() - i)
        mockTrend.push({
          date: date.toISOString().split('T')[0],
          score: Math.max(0, Math.min(10, 4 + Math.random() * 3 + Math.sin(i / 5) * 1.5)),
        })
      }
      setRiskTrend(mockTrend)
    } catch (error) {
      console.error('Failed to load risk trend:', error)
    }
  }

  useEffect(() => {
    fetchDashboard()
    fetchRiskTrend()
  }, [])

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
    { label: 'Total Assets', value: data?.assets ?? 0, icon: Server, color: 'bg-primary-100 text-primary-600', trend: '+2', trendUp: true },
    { label: 'Total Findings', value: data?.findings ?? 0, icon: AlertTriangle, color: 'bg-danger-100 text-danger-600', trend: '+5', trendUp: false },
    { label: 'Critical', value: data?.critical ?? 0, icon: AlertTriangle, color: 'bg-danger-100 text-danger-600', trend: '0', trendUp: null },
    { label: 'High', value: data?.high ?? 0, icon: AlertTriangle, color: 'bg-warning-100 text-warning-600', trend: '+2', trendUp: false },
  ]

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-600 border-t-transparent" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
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

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <div key={stat.label} className="card p-6">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm text-gray-500">{stat.label}</p>
                <p className="text-3xl font-bold text-gray-900 mt-1">{stat.value}</p>
                <div className="flex items-center gap-1 mt-2">
                  {stat.trendUp !== null && (
                    <>
                      {stat.trendUp ? (
                        <ArrowUpRight className="w-4 h-4 text-danger-600" />
                      ) : (
                        <ArrowDownRight className="w-4 h-4 text-success-600" />
                      )}
                      <span className={`text-sm font-medium ${stat.trendUp ? 'text-danger-600' : 'text-success-600'}`}>
                        {stat.trend} vs last week
                      </span>
                    </>
                  )}
                  {stat.trendUp === null && (
                    <span className="text-sm text-gray-500">No change</span>
                  )}
                </div>
              </div>
              <div className={`p-3 rounded-xl ${stat.color}`}>
                <stat.icon className="w-6 h-6" />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Trend */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Risk Score Trend (30 days)</h3>
            <span className="text-sm text-gray-500">Avg: {riskTrend.length ? (riskTrend.reduce((a, b) => a + b.score, 0) / riskTrend.length).toFixed(1) : '0'}/10</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={riskTrend}>
                <defs>
                  <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="date" stroke="#9ca3af" tick={{ fill: '#6b7280', fontSize: 11 }} interval="preserveStartEnd" tickCount={6} />
                <YAxis stroke="#9ca3af" tick={{ fill: '#6b7280', fontSize: 11 }} domain={[0, 10]} />
                <Tooltip
                  contentStyle={{ backgroundColor: 'white', border: '1px solid #e5e7eb', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}
                  formatter={(value: number) => [value.toFixed(1), 'Risk Score']}
                />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="#dc2626"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#riskGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Findings by Severity */}
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
                <div className="w-3 h-3 rounded" style={{ backgroundColor: s.color }} />
                <span className="text-sm text-gray-600">{s.severity}: {s.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Activity & Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Quick Actions</h3>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <button className="btn-secondary flex flex-col items-center gap-2 p-4">
              <Plus className="w-6 h-6" />
              <span className="text-sm font-medium">Add Asset</span>
            </button>
            <button className="btn-secondary flex flex-col items-center gap-2 p-4">
              <Scan className="w-6 h-6" />
              <span className="text-sm font-medium">Start Scan</span>
            </button>
            <button className="btn-secondary flex flex-col items-center gap-2 p-4">
              <FileText className="w-6 h-6" />
              <span className="text-sm font-medium">Generate Report</span>
            </button>
            <button className="btn-secondary flex flex-col items-center gap-2 p-4">
              <AlertTriangle className="w-6 h-6" />
              <span className="text-sm font-medium">View Findings</span>
            </button>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Recent Scans</h3>
            <span className="text-sm text-gray-500">Last 5 scans</span>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-green-100 flex items-center justify-center">
                  <CheckCircle className="w-5 h-5 text-green-600" />
                </div>
                <div>
                  <p className="font-medium text-gray-900">example.com</p>
                  <p className="text-sm text-gray-500">Full scan completed</p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <Clock className="w-4 h-4" />
                <span>2 hours ago</span>
              </div>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-blue-100 flex items-center justify-center">
                  <Clock className="w-5 h-5 text-blue-600" />
                </div>
                <div>
                  <p className="font-medium text-gray-900">api.example.com</p>
                  <p className="text-sm text-gray-500">Scan in progress...</p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <span className="px-2 py-1 bg-blue-100 text-blue-700 rounded-full text-xs">Running</span>
              </div>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-green-100 flex items-center justify-center">
                  <CheckCircle className="w-5 h-5 text-green-600" />
                </div>
                <div>
                  <p className="font-medium text-gray-900">web.example.com</p>
                  <p className="text-sm text-gray-500">Passive scan completed</p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <Clock className="w-4 h-4" />
                <span>1 day ago</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}