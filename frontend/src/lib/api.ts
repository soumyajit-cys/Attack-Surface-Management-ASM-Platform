import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios'
import type { Asset, Finding, Scan, ScanPolicy, AlertIntegration, Invitation, APIKey, DigestConfig, PaginatedResponse, DashboardData } from './types'
import type { AssetGraphData } from '../AssetGraph'

export const API_PREFIX = import.meta.env.VITE_API_BASE || '/api/v1'

/** Pull a human-readable message out of the v1 error envelope. */
export function getApiErrorMessage(error: unknown, fallback = 'Something went wrong'): string {
  if (axios.isAxiosError(error)) {
    const envelope = error.response?.data as { error?: { message?: string } } | undefined
    if (envelope?.error?.message) return envelope.error.message
    if (typeof error.response?.data === 'string' && error.response.data) return error.response.data
    if (error.message) return error.message
  }
  return fallback
}

export interface AuthUser {
  id: number
  username: string
  email: string
  role: string
  organization_id: number
  organization_name: string | null
  permissions: string[]
}

export interface TokenBundle {
  access_token: string
  refresh_token: string
  user?: AuthUser
}

class ApiClient {
  private client: AxiosInstance
  private accessToken: string | null = null
  private refreshToken: string | null = null
  private isRefreshing = false
  private failedQueue: Array<{
    resolve: (value: unknown) => void
    reject: (reason: unknown) => void
  }> = []

  constructor() {
    this.client = axios.create({
      baseURL: API_PREFIX,
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true,
    })

    this.client.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        if (this.accessToken) {
          config.headers.Authorization = `Bearer ${this.accessToken}`
        }
        const apiKey = localStorage.getItem('api_key')
        if (apiKey && !config.headers.Authorization) {
          config.headers['X-API-Key'] = apiKey
        }
        return config
      },
      (error) => Promise.reject(error)
    )

    this.client.interceptors.response.use(
      (response) => response.data,
      async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

        if (error.response?.status === 401 && !originalRequest._retry) {
          if (this.isRefreshing) {
            return new Promise((resolve, reject) => {
              this.failedQueue.push({ resolve, reject })
            })
              .then((token) => {
                originalRequest.headers.Authorization = `Bearer ${token}`
                return this.client(originalRequest)
              })
              .catch((err) => Promise.reject(err))
          }

          originalRequest._retry = true
          this.isRefreshing = true

          try {
            const response = await axios.post(`${API_PREFIX}/auth/refresh`, {
              refresh_token: this.refreshToken,
            })
            const { access_token, refresh_token } = response.data
            this.setTokens(access_token, refresh_token)
            this.processQueue(null, access_token)
            originalRequest.headers.Authorization = `Bearer ${access_token}`
            return this.client(originalRequest)
          } catch (err) {
            this.processQueue(err instanceof Error ? err : new Error(String(err)), null)
            this.clearTokens()
            window.location.href = '/login'
            return Promise.reject(err)
          } finally {
            this.isRefreshing = false
          }
        }

        return Promise.reject(error)
      }
    )
  }

  setTokens(access: string, refresh: string) {
    this.accessToken = access
    this.refreshToken = refresh
    localStorage.setItem('access_token', access)
    localStorage.setItem('refresh_token', refresh)
  }

  clearTokens() {
    this.accessToken = null
    this.refreshToken = null
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('api_key')
  }

  loadTokens() {
    this.accessToken = localStorage.getItem('access_token')
    this.refreshToken = localStorage.getItem('refresh_token')
  }

  setApiKey(key: string) {
    localStorage.setItem('api_key', key)
  }

  get isAuthenticated(): boolean {
    return !!this.accessToken
  }

  private processQueue(error: Error | null, token: string | null) {
    this.failedQueue.forEach(({ resolve, reject }) => {
      if (error) reject(error)
      else resolve(token)
    })
    this.failedQueue = []
  }

  private get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.client.get<T, T>(url, config) as Promise<T>
  }

  private post<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return this.client.post<T, T>(url, data, config) as Promise<T>
  }

  private patch<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return this.client.patch<T, T>(url, data, config) as Promise<T>
  }

  private delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.client.delete<T, T>(url, config) as Promise<T>
  }

  // ── auth ───────────────────────────────────────────────────────────────────
  async login(username: string, password: string): Promise<TokenBundle> {
    return this.post<TokenBundle>('/auth/login', { username, password })
      .then((data) => {
        this.setTokens(data.access_token, data.refresh_token)
        return data
      })
  }

  async register(data: { username: string; email: string; password: string; organization: string }): Promise<TokenBundle> {
    return this.post<TokenBundle>('/auth/register', data)
      .then((bundle) => {
        this.setTokens(bundle.access_token, bundle.refresh_token)
        return bundle
      })
  }

  async logout() {
    await this.post('/auth/logout', {
      refresh_token: this.refreshToken,
    })
    this.clearTokens()
  }

  async getMe(): Promise<AuthUser> {
    return this.get<AuthUser>('/auth/me')
  }

  // ── dashboard / assets ─────────────────────────────────────────────────────
  async getDashboard(): Promise<DashboardData> {
    return this.get<DashboardData>('/dashboard')
  }

  async getAssets(params?: { page?: number; page_size?: number; search?: string; criticality?: string }): Promise<PaginatedResponse<Asset>> {
    return this.get<PaginatedResponse<Asset>>('/assets', { params })
  }

  async getAsset(assetId: number) {
    return this.get<{
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
      domains: Array<Record<string, unknown>>
    }>(`/assets/${assetId}`)
  }

  async getAssetGraph(assetId: number) {
    return this.get<AssetGraphData>(`/assets/${assetId}/graph`)
  }

  // ── findings ───────────────────────────────────────────────────────────────
  async getFindings(params?: { page?: number; page_size?: number; severity?: string; category?: string; asset_id?: number }): Promise<PaginatedResponse<Finding>> {
    return this.get<PaginatedResponse<Finding>>('/findings', { params })
  }

  async getFinding(findingId: number): Promise<Finding> {
    return this.get<Finding>(`/findings/${findingId}`)
  }

  // ── scans ──────────────────────────────────────────────────────────────────
  async startScan(domain: string) {
    return this.post('/scans', { domain })
  }

  async getScans(params?: { page?: number; page_size?: number; status?: string }): Promise<PaginatedResponse<Scan>> {
    return this.get<PaginatedResponse<Scan>>('/scans', { params })
  }

  // ── scan policies ──────────────────────────────────────────────────────────
  async getScanPolicies(): Promise<ScanPolicy[]> {
    return this.get<ScanPolicy[]>('/scan-policies')
  }

  async createScanPolicy(data: { name: string; asset_id: number; frequency: string; scope: string; cron_expression?: string | null }): Promise<ScanPolicy> {
    return this.post<ScanPolicy>('/scan-policies', data)
  }

  async updateScanPolicy(policyId: number, data: Partial<{ name: string; frequency: string; scope: string; cron_expression: string; is_active: boolean }>) {
    return this.patch(`/scan-policies/${policyId}`, data)
  }

  async deleteScanPolicy(policyId: number) {
    return this.delete(`/scan-policies/${policyId}`)
  }

  async runScanPolicy(policyId: number) {
    return this.post(`/scan-policies/${policyId}/run-now`)
  }

  // ── organizations ──────────────────────────────────────────────────────────
  async getOrganization() {
    return this.get('/organizations/me')
  }

  async listInvitations(): Promise<Invitation[]> {
    return this.get<Invitation[]>('/organizations/invitations')
  }

  async createInvitation(email: string, role: string) {
    return this.post('/organizations/invitations', { email, role })
  }

  async revokeInvitation(id: number) {
    return this.post(`/organizations/invitations/${id}/revoke`)
  }

  async listApiKeys(): Promise<APIKey[]> {
    return this.get<APIKey[]>('/organizations/api-keys')
  }

  async createApiKey(data: { name: string; scopes: string; expires_days?: number }): Promise<APIKey & { key: string }> {
    return this.post('/organizations/api-keys', data)
  }

  async deleteApiKey(id: number) {
    return this.delete(`/organizations/api-keys/${id}`)
  }

  // ── alerting ───────────────────────────────────────────────────────────────
  async createAlertIntegration(data: { name: string; channel: string; webhook_url: string; min_severity: string; secret?: string }) {
    return this.post('/alerting/integrations', data)
  }

  async listAlertIntegrations(): Promise<AlertIntegration[]> {
    return this.get<AlertIntegration[]>('/alerting/integrations')
  }

  async deleteAlertIntegration(id: number) {
    return this.delete(`/alerting/integrations/${id}`)
  }

  async testAlertIntegration(id: number) {
    return this.post(`/alerting/integrations/${id}/test`)
  }

  async getDigestConfig(): Promise<DigestConfig> {
    return this.get<DigestConfig>('/alerting/digest')
  }

  async createDigestConfig(data: { frequency: string; day_of_week: number; hour_utc: number; recipient_emails: string; min_severity: string }) {
    return this.post('/alerting/digest', data)
  }

  async updateDigestConfig(data: Partial<{ frequency: string; day_of_week: number; hour_utc: number; recipient_emails: string; min_severity: string; is_active: boolean }>) {
    return this.patch('/alerting/digest', data)
  }

  async deleteDigestConfig() {
    return this.delete('/alerting/digest')
  }

  // ── reports ────────────────────────────────────────────────────────────────
  async exportFindingsCsv(params?: { asset_id?: number; since?: string; severity?: string }) {
    return this.post<Blob>('/reports/export/findings/csv', params ?? {}, {
      responseType: 'blob',
    })
  }

  async exportAssetsCsv() {
    return this.post<Blob>('/reports/export/assets/csv', {}, {
      responseType: 'blob',
    })
  }

  async exportScansCsv(params?: { since?: string }) {
    return this.post<Blob>('/reports/export/scans/csv', params ?? {}, {
      responseType: 'blob',
    })
  }

  async exportDomainsCsv() {
    return this.post<Blob>('/reports/export/domains/csv', {}, {
      responseType: 'blob',
    })
  }

  async exportAllCsv() {
    return this.post<Blob>('/reports/export/all/csv', {}, {
      responseType: 'blob',
    })
  }

  async getExecutiveSummaryPdf(assetId?: number, since?: string) {
    const params: Record<string, string | number> = {}
    if (assetId) params.asset_id = assetId
    if (since) params.since = since
    return this.get<Blob>('/reports/pdf/executive-summary', {
      params,
      responseType: 'blob',
    })
  }

  async getFindingPdf(findingId: number) {
    return this.get<Blob>(`/reports/pdf/finding/${findingId}`, {
      responseType: 'blob',
    })
  }
}

export const api = new ApiClient()
