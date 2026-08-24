import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios'

const API_BASE = import.meta.env.VITE_API_BASE || ''

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
      baseURL: API_BASE,
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
            const response = await axios.post(`${API_BASE}/auth/refresh`, {
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
  }

  loadTokens() {
    this.accessToken = localStorage.getItem('access_token')
    this.refreshToken = localStorage.getItem('refresh_token')
  }

  private processQueue(error: Error | null, token: string | null) {
    this.failedQueue.forEach(({ resolve, reject }) => {
      if (error) reject(error)
      else resolve(token)
    })
    this.failedQueue = []
  }

  async login(username: string, password: string) {
    const response = await this.client.post('/auth/login', { username, password })
    const { access_token, refresh_token } = response.data
    this.setTokens(access_token, refresh_token)
    return response.data
  }

  async register(data: { username: string; email: string; password: string; organization: string }) {
    const response = await this.client.post('/auth/register', data)
    const { access_token, refresh_token } = response.data
    this.setTokens(access_token, refresh_token)
    return response.data
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

  async getDashboard() {
    return this.client.get('/dashboard/')
  }

  async getFindings(params?: { page?: number; page_size?: number; severity?: string }) {
    return this.client.get('/findings/', { params })
  }

  async getScanPolicies() {
    return this.client.get('/scan-policies/')
  }

  async createScanPolicy(data: { name: string; asset_id: number; frequency: string; scope: string }) {
    return this.client.post('/scan-policies/', data)
  }

  async runScanPolicy(policyId: number) {
    return this.client.post(`/scan-policies/${policyId}/run-now`)
  }

  async startScan(domain: string) {
    return this.client.post('/scan/', { domain })
  }

  async getScanStatus(scanId: number) {
    return this.client.get(`/scan/${scanId}`)
  }

  async getAssetGraph(assetId: number) {
    return this.client.get(`/graph/asset/${assetId}`)
  }

  async getOrganizations() {
    return this.client.get('/organizations/me')
  }

  async createOrganization(name: string) {
    return this.client.post('/organizations/', { name })
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

  async deleteApiKey(id: number) {
    return this.client.delete(`/organizations/api-keys/${id}`)
  }

  async createAlertIntegration(data: { name: string; channel: string; webhook_url: string; min_severity: string }) {
    return this.client.post('/alerting/integrations', data)
  }

  async listAlertIntegrations() {
    return this.client.get('/alerting/integrations')
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

  async exportFindingsCsv(params?: { asset_id?: number; since?: string; severity?: string }) {
    const response = await this.client.post('/reports/export/findings/csv', params, {
      responseType: 'blob',
    })
    return response.data
  }

  async exportAssetsCsv() {
    const response = await this.client.post('/reports/export/assets/csv', {}, {
      responseType: 'blob',
    })
    return response.data
  }

  async exportAllCsv() {
    const response = await this.client.post('/reports/export/all/csv', {}, {
      responseType: 'blob',
    })
    return response.data
  }

  async getExecutiveSummaryPdf(assetId?: number) {
    const params = assetId ? { asset_id: assetId } : {}
    const response = await this.client.get('/reports/pdf/executive-summary', {
      params,
      responseType: 'blob',
    })
    return response.data
  }
}

export const api = new ApiClient()