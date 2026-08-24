import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './contexts/AuthContext'
import { Layout } from './components/Layout'
import { Login } from './pages/Login'
import { Register } from './pages/Register'
import { Dashboard } from './pages/Dashboard'
import { Assets } from './pages/Assets'
import { AssetDetail } from './pages/AssetDetail'
import { Findings } from './pages/Findings'
import { FindingDetail } from './pages/FindingDetail'
import { Scans } from './pages/Scans'
import { ScanPolicies } from './pages/ScanPolicies'
import { Organizations } from './pages/Organizations'
import { Alerting } from './pages/Alerting'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="min-h-screen flex items-center justify-center">Loading...</div>
  return user ? <>{children}</> : <Navigate to="/login" replace />
}

export function Router() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="assets" element={<Assets />} />
        <Route path="assets/:id" element={<AssetDetail />} />
        <Route path="findings" element={<Findings />} />
        <Route path="findings/:id" element={<FindingDetail />} />
        <Route path="scans" element={<Scans />} />
        <Route path="scan-policies" element={<ScanPolicies />} />
        <Route path="organizations" element={<Organizations />} />
        <Route path="alerting" element={<Alerting />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}