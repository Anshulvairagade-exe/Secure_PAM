import { Routes, Route } from 'react-router-dom';

import ProtectedRoute from '@/components/ProtectedRoute';
import AppLayout from '@/layouts/AppLayout';
import Login from '@/pages/Login';
import Dashboard from '@/pages/Dashboard';
import Assets from '@/pages/Assets';
import Applications from '@/pages/Applications';
import Policies from '@/pages/Policies';
import AccessRequests from '@/pages/AccessRequests';
import AccessRequestNew from '@/pages/AccessRequestNew';
import AccessRequestDetail from '@/pages/AccessRequestDetail';
import ApprovalsPage from '@/pages/Approvals';
import AuditLogs from '@/pages/AuditLogs';
import VaultReferences from '@/pages/VaultReferences';
import Sessions from '@/pages/Sessions';
import AdminSessions from '@/pages/AdminSessions';
import Recordings from '@/pages/Recordings';
import SettingsPage from '@/pages/SettingsPage';
import Users from '@/pages/Users';
import Roles from '@/pages/Roles';
import RiskCenter from '@/pages/RiskCenter';
import NotFound from '@/pages/NotFound';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/access-requests" element={<AccessRequests />} />
        <Route path="/access-requests/new" element={<AccessRequestNew />} />
        <Route path="/access-requests/:id" element={<AccessRequestDetail />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route
          path="/admin/sessions"
          element={
            <ProtectedRoute requiredRoles={['ADMIN']}>
              <AdminSessions />
            </ProtectedRoute>
          }
        />
        <Route path="/assets" element={<Assets />} />
        <Route path="/applications" element={<Applications />} />
        <Route
          path="/approvals"
          element={
            <ProtectedRoute requiredRoles={['ADMIN', 'APPROVER', 'AUDITOR']}>
              <ApprovalsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/recordings"
          element={
            <ProtectedRoute requiredRoles={['ADMIN', 'AUDITOR']}>
              <Recordings />
            </ProtectedRoute>
          }
        />
        <Route
          path="/audit"
          element={
            <ProtectedRoute requiredRoles={['ADMIN', 'AUDITOR']}>
              <AuditLogs />
            </ProtectedRoute>
          }
        />
        <Route
          path="/risk"
          element={
            <ProtectedRoute requiredRoles={['ADMIN', 'APPROVER', 'AUDITOR']}>
              <RiskCenter />
            </ProtectedRoute>
          }
        />
        <Route
          path="/policies"
          element={
            <ProtectedRoute requiredRoles={['ADMIN', 'APPROVER', 'AUDITOR']}>
              <Policies />
            </ProtectedRoute>
          }
        />
        <Route
          path="/vault"
          element={
            <ProtectedRoute requiredRoles={['ADMIN']}>
              <VaultReferences />
            </ProtectedRoute>
          }
        />
        <Route
          path="/users"
          element={
            <ProtectedRoute requiredRoles={['ADMIN']}>
              <Users />
            </ProtectedRoute>
          }
        />
        <Route
          path="/roles"
          element={
            <ProtectedRoute requiredRoles={['ADMIN']}>
              <Roles />
            </ProtectedRoute>
          }
        />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
