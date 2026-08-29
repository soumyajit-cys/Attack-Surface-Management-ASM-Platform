import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios'

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
      (response) => response,
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
            this.processQueue(err, null)
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

  // ── auth ───────────────────────────────────────────────────────────────────
  async login(username: string, password: string): Promise<TokenBundle> {
    const response = await this.client.post<TokenBundle>('/auth/login', { username, password })
    const data = response.data
    this.setTokens(data.access_token, data.refresh_token)
    return data
  }

  async register(data: { username: string; email: string; password: string; organization: string }): Promise<TokenBundle> {
    const response = await this.client.post<TokenBundle>('/auth/register', data)
    const bundle = response.data
    this.setTokens(bundle.access_token, bundle.refresh_token)
    return bundle
  }

  async refresh() {
    const response = await this.client.post('/auth/refresh', {
      refresh_token: this.refreshToken,
    })
    const { access_token, refresh_token } = response.data
    this.setTokens(access_token, refresh_token)
    return response.data
  }

  async logout() {
    await this.client.post('/auth/logout', {
      refresh_token: this.refreshToken,
    })
    this.clearTokens()
  }

  async forgotPassword(email: string) {
    return this.client.post('/auth/forgot-password', { email })
  }

  async resetPassword(token: string, newPassword: string) {
    return this.client.post('/auth/reset-password', { token, new_password: newPassword })
  }

  async getMe() {
    return this.client.get('/auth/me')
  }

  // ── dashboard / assets ─────────────────────────────────────────────────────
  async getDashboard() {
    return this.client.get('/dashboard')
  }

  async getAssets(params?: { page?: number; page_size?: number; search?: string; criticality?: string }) {
    return this.client.get('/assets', { params })
  }

  async getAsset(assetId: number) {
    return this.client.get(`/assets/${assetId}`)
  }

  async getAssetGraph(assetId: number) {
    return this.client.get(`/assets/${assetId}/graph`)
  }

  // ── findings ───────────────────────────────────────────────────────────────
  async getFindings(params?: { page?: number; page_size?: number; severity?: string; category?: string; asset_id?: number }) {
    return this.client.get('/findings', { params })
  }

  async getFinding(findingId: number) {
    return this.client.get(`/findings/${findingId}`)
  }

  // ── scans ──────────────────────────────────────────────────────────────────
  async startScan(domain: string) {
    return this.client.post('/scans', { domain })
  }

  async getScans(params?: { page?: number; page_size?: number; status?: string }) {
    return this.client.get('/scans', { params })
  }

  async getScanStatus(scanId: number) {
    return this.client.get(`/scans/${scanId}`)
  }

  async verifyOwnershipChallenge(domain: string) {
    return this.client.post('/scans/verify-ownership', { domain })
  }

  async checkOwnership(domain: string, token: string) {
    return this.client.get('/scans/verify-ownership/check', { params: { domain, token } })
  }

  // ── scan policies ──────────────────────────────────────────────────────────
  async getScanPolicies() {
    return this.client.get('/scan-policies')
  }

  async createScanPolicy(data: { name: string; asset_id: number; frequency: string; scope: string; cron_expression?: string | null }) {
    return this.client.post('/scan-policies', data)
  }

  async updateScanPolicy(policyId: number, data: Partial<{ name: string; frequency: string; scope: string; cron_expression: string; is_active: boolean }>) {
    return this.client.patch(`/scan-policies/${policyId}`, data)
  }

  async deleteScanPolicy(policyId: number) {
    return this.client.delete(`/scan-policies/${policyId}`)
  }

  async runScanPolicy(policyId: number) {
    return this.client.post(`/scan-policies/${policyId}/run-now`)
  }

  // ── organizations ──────────────────────────────────────────────────────────
  async getOrganizations() {
    return this.client.get('/organizations/me')
  }

  async createInvitation(email: string, role: string) {
    return this.client.post('/organizations/invitations', { email, role })
  }

  async listInvitations() {
    return this.client.get('/organizations/invitations')
  }

  async revokeInvitation(id: number) {
    return this.client.post(`/organizations/invitations/${id}/revoke`)
  }

  async createApiKey(data: { name: string; scopes: string; expires_days?: number }) {
    return this.client.post('/organizations/api-keys', data)
  }

  async listApiKeys() {
    return this.client.get('/organizations/api-keys')
  }

  async updateApiKey(id: number, data: Partial<{ name: string; scopes: string; is_active: boolean }>) {
    return this.client.patch(`/organizations/api-keys/${id}`, data)
  }

  async deleteApiKey(id: number) {
    return this.client.delete(`/organizations/api-keys/${id}`)
  }

  // ── alerting ───────────────────────────────────────────────────────────────
  async createAlertIntegration(data: { name: string; channel: string; webhook_url: string; min_severity: string }) {
    return this.client.post('/alerting/integrations', data)
  }

  async listAlertIntegrations() {
    return this.client.get('/alerting/integrations')
  }

  async deleteAlertIntegration(id: number) {
    return this.client.delete(`/alerting/integrations/${id}`)
  }

  async testAlertIntegration(id: number) {
    return this.client.post(`/alerting/integrations/${id}/test`)
  }

  async createDigestConfig(data: { frequency: string; day_of_week: number; hour_utc: number; recipient_emails: string; min_severity: string }) {
    return this.client.post('/alerting/digest', data)
  }

  async getDigestConfig() {
    return this.client.get('/alerting/digest')
  }

  async updateDigestConfig(data: Partial<{ frequency: string; day_of_week: number; hour_utc: number; recipient_emails: string; min_severity: string; is_active: boolean }>) {
    return this.client.patch('/alerting/digest', data)
  }

  async deleteDigestConfig() {
    return this.client.delete('/alerting/digest')
  }

  // ── reports ────────────────────────────────────────────────────────────────
  async exportFindingsCsv(params?: { asset_id?: number; since?: string; severity?: string }) {
    const response = await this.client.post('/reports/export/findings/csv', params ?? {}, {
      responseType: 'blob',
    })
    return response.data as Blob
  }

  async exportAssetsCsv() {
    const response = await this.client.post('/reports/export/assets/csv', {}, {
      responseType: 'blob',
    })
    return response.data as Blob
  }

  async exportScansCsv(params?: { since?: string }) {
    const response = await this.client.post('/reports/export/scans/csv', params ?? {}, {
      responseType: 'blob',
    })
    return response.data as Blob
  }

  async exportDomainsCsv() {
    const response = await this.client.post('/reports/export/domains/csv', {}, {
      responseType: 'blob',
    })
    return response.data as Blob
  }

  async exportAllCsv() {
    const response = await this.client.post('/reports/export/all/csv', {}, {
      responseType: 'blob',
    })
    return response.data as Blob
  }

  async getExecutiveSummaryPdf(assetId?: number, since?: string) {
    const params: Record<string, string | number> = {}
    if (assetId) params.asset_id = assetId
    if (since) params.since = since
    const response = await this.client.get('/reports/pdf/executive-summary', {
      params,
      responseType: 'blob',
    })
    return response.data as Blob
  }

  async getFindingPdf(findingId: number) {
    const response = await this.client.get(`/reports/pdf/finding/${findingId}`, {
      responseType: 'blob',
    })
    return response.data as Blob
  }
}

export const api = new ApiClient()