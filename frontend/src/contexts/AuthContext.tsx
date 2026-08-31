import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { api, AuthUser } from '../lib/api'

interface Organization {
  id: number
  name: string
}

interface AuthContextType {
  user: AuthUser | null
  organization: Organization | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  register: (data: { username: string; email: string; password: string; organization: string }) => Promise<void>
  logout: () => Promise<void>
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [organization, setOrganization] = useState<Organization | null>(null)
  const [loading, setLoading] = useState(true)

  const applyUser = useCallback((u: AuthUser) => {
    setUser(u)
    setOrganization({ id: u.organization_id, name: u.organization_name || '' })
  }, [])

  const refreshUser = useCallback(async () => {
    try {
      const response = await api.getMe()
      applyUser(response)
    } catch {
      setUser(null)
      setOrganization(null)
    }
  }, [applyUser])

  useEffect(() => {
    api.loadTokens()
    if (api.isAuthenticated) {
      refreshUser().finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [refreshUser])

  const login = async (username: string, password: string) => {
    const bundle = await api.login(username, password)
    if (bundle.user) applyUser(bundle.user)
    else await refreshUser()
  }

  const register = async (data: { username: string; email: string; password: string; organization: string }) => {
    const bundle = await api.register(data)
    if (bundle.user) applyUser(bundle.user)
    else await refreshUser()
  }

  const logout = async () => {
    await api.logout()
    setUser(null)
    setOrganization(null)
  }

  return (
    <AuthContext.Provider value={{ user, organization, loading, login, register, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
