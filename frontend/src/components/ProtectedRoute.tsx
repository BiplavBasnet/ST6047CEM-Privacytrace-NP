import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { LoadingState } from "./LoadingError";
import UnassignedPage from "../pages/UnassignedPage";

export default function ProtectedRoute() {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingState message="Checking session…" />;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}

export function AssignedRoute() {
  const { user } = useAuth();
  if (user?.membership?.status === "pending") {
    return <Navigate to="/setup" replace />;
  }
  if (!user?.membership || user.membership.status !== "active") {
    return <UnassignedPage />;
  }
  return <Outlet />;
}
