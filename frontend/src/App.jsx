import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import LogExplorer from "./pages/LogExplorer";
import Detections from "./pages/Detections";
import Anomalies from "./pages/Anomalies";
import Network from "./pages/Network";
import Devices from "./pages/Devices";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Recommendations from "./pages/Recommendations";
import AuditLog from "./pages/AuditLog";
import Report from "./pages/Report";
import Upload from "./pages/Upload";
import Settings from "./pages/Settings";
import AttackMatrix from "./pages/AttackMatrix";
import TechniqueDetail from "./pages/TechniqueDetail";

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/events" element={<LogExplorer />} />
            <Route path="/detections" element={<Detections />} />
            <Route path="/anomalies" element={<Anomalies />} />
            <Route path="/network" element={<Network />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/attack" element={<AttackMatrix />} />
            <Route path="/attack/:techniqueId" element={<TechniqueDetail />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/incidents/:id/report" element={<Report />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/recommendations" element={<Recommendations />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
