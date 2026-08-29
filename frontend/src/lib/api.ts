import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios'

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

  // Response interceptors unwrap `response.data`, so these helpers type the
  // public methods as returning the payload directly.
  private get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.client.get<T, T>(url, config) as Promise<T>
  }

  private post<T = any>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return this.client.post<T, T>(url, data, config) as Promise<T>
  }

  private patch<T = any>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return this.client.patch<T, T>(url, data, config) as Promise<T>
  }

  private delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
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

  async refresh() {
    return this.post<{ access_token: string; refresh_token: string }>('/auth/refresh', {
      refresh_token: this.refreshToken,
    })
      .then((data) => {
        this.setTokens(data.access_token, data.refresh_token)
        return data
      })
  }

  async logout() {
    await this.post('/auth/logout', {
      refresh_token: this.refreshToken,
    })
    this.clearTokens()
  }

  async forgotPassword(email: string) {
    return this.post('/auth/forgot-password', { email })
  }

  async resetPassword(token: string, newPassword: string) {
    return this.post('/auth/reset-password', { token, new_password: newPassword })
  }

  async getMe() {
    return this.get('/auth/me')
  }

  // ── dashboard / assets ─────────────────────────────────────────────────────
  async getDashboard() {
    return this.get('/dashboard')
  }

  async getAssets(params?: { page?: number; page_size?: number; search?: string; criticality?: string }) {
    return this.get('/assets', { params })
  }

  async getAsset(assetId: number) {
    return this.get(`/assets/${assetId}`)
  }

  async getAssetGraph(assetId: number) {
    return this.get(`/assets/${assetId}/graph`)
  }

  // ── findings ───────────────────────────────────────────────────────────────
  async getFindings(params?: { page?: number; page_size?: number; severity?: string; category?: string; asset_id?: number }) {
    return this.get('/findings', { params })
  }

  async getFinding(findingId: number) {
    return this.get(`/findings/${findingId}`)
  }

  // ── scans ──────────────────────────────────────────────────────────────────
  async startScan(domain: string) {
    return this.post('/scans', { domain })
  }

  async getScans(params?: { page?: number; page_size?: number; status?: string }) {
    return this.get('/scans', { params })
  }

  async getScanStatus(scanId: number) {
    return this.get(`/scans/${scanId}`)
  }

  async verifyOwnershipChallenge(domain: string) {
    return this.post('/scans/verify-ownership', { domain })
  }

  async checkOwnership(domain: string, token: string) {
    return this.get('/scans/verify-ownership/check', { params: { domain, token } })
  }

  // ── scan policies ──────────────────────────────────────────────────────────
  async getScanPolicies() {
    return this.get('/scan-policies')
  }

  async createScanPolicy(data: { name: string; asset_id: number; frequency: string; scope: string; cron_expression?: string | null }) {
    return this.post('/scan-policies', data)
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
  async getOrganizations() {
    return this.get('/organizations/me')
  }

  async createInvitation(email: string, role: string) {
    return this.post('/organizations/invitations', { email, role })
  }

  async listInvitations() {
    return this.get('/organizations/invitations')
  }

  async revokeInvitation(id: number) {
    return this.post(`/organizations/invitations/${id}/revoke`)
  }

  async createApiKey(data: { name: string; scopes: string; expires_days?: number }) {
    return this.post('/organizations/api-keys', data)
  }

  async listApiKeys() {
    return this.get('/organizations/api-keys')
  }

  async updateApiKey(id: number, data: Partial<{ name: string; scopes: string; is_active: boolean }>) {
    return this.patch(`/organizations/api-keys/${id}`, data)
  }

  async deleteApiKey(id: number) {
    return this.delete(`/organizations/api-keys/${id}`)
  }

  // ── alerting ───────────────────────────────────────────────────────────────
  async createAlertIntegration(data: { name: string; channel: string; webhook_url: string; min_severity: string; secret?: string }) {
    return this.post('/alerting/integrations', data)
  }

  async listAlertIntegrations() {
    return this.get('/alerting/integrations')
  }

  async deleteAlertIntegration(id: number) {
    return this.delete(`/alerting/integrations/${id}`)
  }

  async testAlertIntegration(id: number) {
    return this.post(`/alerting/integrations/${id}/test`)
  }

  async createDigestConfig(data: { frequency: string; day_of_week: number; hour_utc: number; recipient_emails: string; min_severity: string }) {
    return this.post('/alerting/digest', data)
  }

  async getDigestConfig() {
    return this.get('/alerting/digest')
  }

  async updateDigestConfig(data: Partial<{ frequency: string; day_of_week: number; hour_utc: number; recipient_emails: string; min_severity: string; is_active: boolean }>) {
    return this.patch('/alerting/digest', data)
  }

  async deleteDigestConfig() {
    return this.delete('/alerting/digest')
  }

  // ── reports ────────────────────────────────────────────────────────────────
  async exportFindingsCsv(params?: { asset_id?: number; since?: string; severity?: string }) {
    return this.client.post<Blob>('/reports/export/findings/csv', params ?? {}, {
      responseType: 'blob',
    })
  }

  async exportAssetsCsv() {
    return this.client.post<Blob>('/reports/export/assets/csv', {}, {
      responseType: 'blob',
    })
  }

  async exportScansCsv(params?: { since?: string }) {
    return this.client.post<Blob>('/reports/export/scans/csv', params ?? {}, {
      responseType: 'blob',
    })
  }

  async exportDomainsCsv() {
    return this.client.post<Blob>('/reports/export/domains/csv', {}, {
      responseType: 'blob',
    })
  }

  async exportAllCsv() {
    return this.client.post<Blob>('/reports/export/all/csv', {}, {
      responseType: 'blob',
    })
  }

  async getExecutiveSummaryPdf(assetId?: number, since?: string) {
    const params: Record<string, string | number> = {}
    if (assetId) params.asset_id = assetId
    if (since) params.since = since
    return this.client.get<Blob>('/reports/pdf/executive-summary', {
      params,
      responseType: 'blob',
    })
  }

  async getFindingPdf(findingId: number) {
    return this.client.get<Blob>(`/reports/pdf/finding/${findingId}`, {
      responseType: 'blob',
    })
  }
}

export const api = new ApiClient()