import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import ProtectedRoute, { AssignedRoute } from "./components/ProtectedRoute";
import { AuthProvider } from "./context/AuthContext";
import AboutPage from "./pages/AboutPage";
import AuditLogsPage from "./pages/AuditLogsPage";
import DemoGuidePage from "./pages/DemoGuidePage";
import EvidencePage from "./pages/EvidencePage";
import PrivacyAlertsPage from "./pages/PrivacyAlertsPage";
import UserGuidePage from "./pages/UserGuidePage";
import HomePage from "./pages/HomePage";
import IncidentDetailPage from "./pages/IncidentDetailPage";
import IncidentsPage from "./pages/IncidentsPage";
import Integrations from "./pages/Integrations";
import ScannerBridgePage from "./pages/ScannerBridge";
import InvestigationWizard from "./pages/InvestigationWizard";
import LivePrivacyMonitorPage from "./pages/LivePrivacyMonitor";
import AuthPage from "./pages/AuthPage";
import MetricsPage from "./pages/MetricsPage";
import ReportsPage from "./pages/ReportsPage";
import SecurityPage from "./pages/SecurityPage";
import SetupPage from "./pages/SetupPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import TaxonomyPage from "./pages/TaxonomyPage";
import UserManagementPage from "./pages/UserManagement";

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<AuthPage />} />
        <Route path="/signup" element={<AuthPage />} />
        <Route path="/setup" element={<SetupPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route element={<AssignedRoute />}>
              <Route index element={<HomePage />} />
              <Route path="incidents" element={<IncidentsPage />} />
              <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
              <Route path="incidents/:incidentId/:stage" element={<IncidentDetailPage />} />
              <Route path="evidence" element={<EvidencePage />} />
              <Route path="wizard" element={<InvestigationWizard />} />
              <Route path="guided-investigation" element={<InvestigationWizard />} />
              <Route path="demo" element={<DemoGuidePage />} />
              <Route path="live-monitor" element={<LivePrivacyMonitorPage />} />
              <Route path="alerts" element={<PrivacyAlertsPage />} />
              <Route path="integrations" element={<Integrations />} />
              <Route path="scanner-bridge" element={<ScannerBridgePage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="metrics" element={<MetricsPage />} />
              <Route path="users" element={<UserManagementPage />} />
              <Route path="security" element={<SecurityPage />} />
              <Route path="taxonomy" element={<TaxonomyPage />} />
              <Route path="audit-logs" element={<AuditLogsPage />} />
            </Route>
            <Route path="help/guide" element={<UserGuidePage />} />
            <Route path="help/demo" element={<DemoGuidePage />} />
            <Route path="help/about" element={<AboutPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Route>
      </Routes>
    </AuthProvider>
  );
}
