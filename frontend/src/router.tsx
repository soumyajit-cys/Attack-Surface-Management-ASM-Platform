import React, { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './contexts/AuthContext'
import { Layout } from './components/Layout'

const Login = lazy(() => import('./pages/Login').then(m => ({ default: m.Login })))
const Register = lazy(() => import('./pages/Register').then(m => ({ default: m.Register })))
const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const Assets = lazy(() => import('./pages/Assets').then(m => ({ default: m.Assets })))
const AssetDetail = lazy(() => import('./pages/AssetDetail').then(m => ({ default: m.AssetDetail })))
const Findings = lazy(() => import('./pages/Findings').then(m => ({ default: m.Findings })))
const FindingDetail = lazy(() => import('./pages/FindingDetail').then(m => ({ default: m.FindingDetail })))
const Scans = lazy(() => import('./pages/Scans').then(m => ({ default: m.Scans })))
const ScanPolicies = lazy(() => import('./pages/ScanPolicies').then(m => ({ default: m.ScanPolicies })))
const Organizations = lazy(() => import('./pages/Organizations').then(m => ({ default: m.Organizations })))
const Alerting = lazy(() => import('./pages/Alerting').then(m => ({ default: m.Alerting })))
const Reports = lazy(() => import('./pages/Reports').then(m => ({ default: m.Reports })))
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.Settings })))

function PageLoader() {
  return (
    <div className="min-h-[50vh] flex items-center justify-center">
      <div className="animate-spin rounded-full h-10 w-10 border-4 border-primary-600 border-t-transparent" />
    </div>
  )
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="min-h-screen flex items-center justify-center">Loading...</div>
  return user ? <>{children}</> : <Navigate to="/login" replace />
}

function LazyPage({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<PageLoader />}>{children}</Suspense>
}

export default function Router() {
  return (
    <Routes>
      <Route path="/login" element={<LazyPage><Login /></LazyPage>} />
      <Route path="/register" element={<LazyPage><Register /></LazyPage>} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<LazyPage><Dashboard /></LazyPage>} />
        <Route path="assets" element={<LazyPage><Assets /></LazyPage>} />
        <Route path="assets/:id" element={<LazyPage><AssetDetail /></LazyPage>} />
        <Route path="findings" element={<LazyPage><Findings /></LazyPage>} />
        <Route path="findings/:id" element={<LazyPage><FindingDetail /></LazyPage>} />
        <Route path="scans" element={<LazyPage><Scans /></LazyPage>} />
        <Route path="scan-policies" element={<LazyPage><ScanPolicies /></LazyPage>} />
        <Route path="organizations" element={<LazyPage><Organizations /></LazyPage>} />
        <Route path="alerting" element={<LazyPage><Alerting /></LazyPage>} />
        <Route path="reports" element={<LazyPage><Reports /></LazyPage>} />
        <Route path="settings" element={<LazyPage><Settings /></LazyPage>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
