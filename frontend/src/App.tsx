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
import ComingSoon from '@/pages/ComingSoon';
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
        <Route path="/sessions" element={<ComingSoon title="My Sessions" phase="Phase 8" />} />
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
              <ComingSoon title="Recording Center" phase="Phase 10 / 14" />
            </ProtectedRoute>
          }
        />
        <Route
          path="/audit"
          element={
            <ProtectedRoute requiredRoles={['ADMIN', 'AUDITOR']}>
              <ComingSoon title="Audit Logs" phase="Phase 15" />
            </ProtectedRoute>
          }
        />
        <Route
          path="/risk"
          element={
            <ProtectedRoute requiredRoles={['ADMIN', 'APPROVER', 'AUDITOR']}>
              <ComingSoon title="Risk Center" phase="Phase 5" />
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
              <ComingSoon title="Vault References" phase="Phase 7" />
            </ProtectedRoute>
          }
        />
        <Route
          path="/users"
          element={
            <ProtectedRoute requiredRoles={['ADMIN']}>
              <ComingSoon title="Users" phase="Phase 3" />
            </ProtectedRoute>
          }
        />
        <Route
          path="/roles"
          element={
            <ProtectedRoute requiredRoles={['ADMIN']}>
              <ComingSoon title="Roles" phase="Phase 3" />
            </ProtectedRoute>
          }
        />
        <Route path="/settings" element={<ComingSoon title="Settings" phase="Phase 16" />} />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
