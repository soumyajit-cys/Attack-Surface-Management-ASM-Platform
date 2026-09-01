export interface DigestConfig {
  id?: number
  frequency: string
  day_of_week: number
  hour_utc: number
  recipient_emails: string
  min_severity: string
  is_active: boolean
}

export interface Finding {
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

export interface Scan {
  id: number
  target: string
  status: string
  error: string | null
  started_at: string
  completed_at: string | null
  updated_at?: string
}

export interface Asset {
  id: number
  name: string
  criticality: string
  exposure?: string
  created_at: string
  updated_at: string
  domains_count: number
  findings_count: number
  open_ports: number
  risk_score: number
}

export interface ScanPolicy {
  id: number
  name: string
  asset_id: number
  asset_name?: string
  frequency: string
  scope: string
  cron_expression?: string | null
  is_active: boolean
  last_run_at: string | null
  next_run_at: string | null
  created_at: string
  updated_at: string
}

export interface AlertIntegration {
  id: number
  name: string
  channel: string
  webhook_url: string
  min_severity: string
  is_active: boolean
  last_triggered_at: string | null
  created_at: string
}

export interface Invitation {
  id: number
  email: string
  role: string
  status: string
  created_at: string
  expires_at: string
}

export interface APIKey {
  id: number
  name: string
  key_prefix: string
  scopes: string
  is_active: boolean
  last_used_at: string | null
  expires_at: string | null
  created_at: string
  key?: string
}

export interface PaginatedResponse<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export interface DashboardData {
  assets: number
  findings: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  scans_total?: number
  scans_completed?: number
  avg_risk_score?: number
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}
