import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import LogExplorer from "./pages/LogExplorer";
import Detections from "./pages/Detections";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Recommendations from "./pages/Recommendations";

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route path="/events" element={<LogExplorer />} />
            <Route path="/detections" element={<Detections />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/recommendations" element={<Recommendations />} />
            <Route path="/" element={<Navigate to="/events" replace />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
