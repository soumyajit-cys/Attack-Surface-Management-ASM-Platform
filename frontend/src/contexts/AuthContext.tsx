import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { api } from '../lib/api'

interface User {
  id: number
  username: string
  email: string
  role: string
  organization_id: number
}

interface Organization {
  id: number
  name: string
}

interface AuthContextType {
  user: User | null
  organization: Organization | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  register: (data: { username: string; email: string; password: string; organization: string }) => Promise<void>
  logout: () => Promise<void>
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [organization, setOrganization] = useState<Organization | null>(null)
  const [loading, setLoading] = useState(true)

  const refreshUser = useCallback(async () => {
    try {
      const response = await api.getMe()
      setUser(response.data)
      setOrganization({ id: response.data.organization_id, name: '' })
    } catch {
      setUser(null)
      setOrganization(null)
    }
  }, [])

  useEffect(() => {
    api.loadTokens()
    if (api.accessToken) {
      refreshUser().finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [refreshUser])

  const login = async (username: string, password: string) => {
    await api.login(username, password)
    await refreshUser()
  }

  const register = async (data: { username: string; email: string; password: string; organization: string }) => {
    await api.register(data)
    await refreshUser()
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