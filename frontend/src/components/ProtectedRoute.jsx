import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { LiveProvider } from "./LiveProvider";

export default function ProtectedRoute() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Live updates only exist for a signed-in session (the stream needs the token).
  return (
    <LiveProvider>
      <Outlet />
    </LiveProvider>
  );
}
