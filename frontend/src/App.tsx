import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import { RedirectIfAuthenticated, RequireAdmin, RequireAuth } from './components/Guards'
import { Spinner } from './components/ui'
import { useAuth } from './context/AuthContext'

import Landing from './pages/Landing'
import Login from './pages/Login'
import Register from './pages/Register'
import ForgotPassword from './pages/ForgotPassword'
import PublicShare from './pages/PublicShare'
import NotFound from './pages/NotFound'
import ErrorPage from './pages/ErrorPage'

// The authenticated area is code-split so the public pages stay small.
const Dashboard = lazy(() => import('./pages/Dashboard'))
const MyFiles = lazy(() => import('./pages/MyFiles'))
const Upload = lazy(() => import('./pages/Upload'))
const FileDetails = lazy(() => import('./pages/FileDetails'))
const ShareFile = lazy(() => import('./pages/ShareFile'))
const SharedWithMe = lazy(() => import('./pages/SharedWithMe'))
const ShareLinks = lazy(() => import('./pages/ShareLinks'))
const AuditLogs = lazy(() => import('./pages/AuditLogs'))
const Profile = lazy(() => import('./pages/Profile'))
const AdminDashboard = lazy(() => import('./pages/admin/AdminDashboard'))
const AdminUsers = lazy(() => import('./pages/admin/AdminUsers'))
const AdminEvents = lazy(() => import('./pages/admin/AdminEvents'))

/** Banner shown when a refresh failed and the session really is over. */
function SessionExpiredBanner() {
  const { sessionExpired, dismissSessionExpired } = useAuth()
  if (!sessionExpired) return null
  return (
    <div className="fixed inset-x-0 top-0 z-50 bg-amber-500 px-4 py-2 text-center text-sm font-medium text-amber-950">
      Your session expired and you were signed out.{' '}
      <a href="/login" className="underline">
        Sign in again
      </a>
      <button
        type="button"
        onClick={dismissSessionExpired}
        className="ml-3 rounded px-2 py-0.5 text-xs ring-1 ring-amber-900/30 hover:bg-amber-400"
      >
        Dismiss
      </button>
    </div>
  )
}

export default function App() {
  return (
    <>
      <SessionExpiredBanner />
      <Suspense fallback={<Spinner label="Loading" />}>
        <Routes>
          {/* public */}
          <Route path="/" element={<Landing />} />
          <Route
            path="/login"
            element={
              <RedirectIfAuthenticated>
                <Login />
              </RedirectIfAuthenticated>
            }
          />
          <Route
            path="/register"
            element={
              <RedirectIfAuthenticated>
                <Register />
              </RedirectIfAuthenticated>
            }
          />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/s/:token" element={<PublicShare />} />
          <Route path="/error" element={<ErrorPage />} />

          {/* authenticated */}
          <Route
            path="/app"
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="files" element={<MyFiles />} />
            <Route path="files/:fileId" element={<FileDetails />} />
            <Route path="files/:fileId/share" element={<ShareFile />} />
            <Route path="upload" element={<Upload />} />
            <Route path="shared-with-me" element={<SharedWithMe />} />
            <Route path="links" element={<ShareLinks />} />
            <Route path="audit" element={<AuditLogs />} />
            <Route path="profile" element={<Profile />} />

            {/* admin — also enforced server-side on every request */}
            <Route
              path="admin"
              element={
                <RequireAdmin>
                  <AdminDashboard />
                </RequireAdmin>
              }
            />
            <Route
              path="admin/users"
              element={
                <RequireAdmin>
                  <AdminUsers />
                </RequireAdmin>
              }
            />
            <Route
              path="admin/events"
              element={
                <RequireAdmin>
                  <AdminEvents />
                </RequireAdmin>
              }
            />
          </Route>

          {/* convenience redirects */}
          <Route path="/dashboard" element={<Navigate to="/app" replace />} />
          <Route path="/files" element={<Navigate to="/app/files" replace />} />

          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
    </>
  )
}
