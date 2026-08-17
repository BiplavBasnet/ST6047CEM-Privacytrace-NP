import { useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import AuthLayout from "../components/auth/AuthLayout";
import LoginForm from "../components/auth/LoginForm";
import SignupForm from "../components/auth/SignupForm";
import { setupApi } from "../api/authClient";
import { useAuth } from "../context/AuthContext";

export default function AuthPage() {
  const { user } = useAuth();
  const location = useLocation();
  const mode = location.pathname.startsWith("/signup") ? "signup" : "login";
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);

  useEffect(() => {
    const heading = document.getElementById("auth-heading");
    heading?.focus();
  }, [mode]);

  useEffect(() => {
    let cancelled = false;
    setupApi
      .status()
      .then((status) => {
        if (!cancelled) setSetupRequired(status.required);
      })
      .catch(() => {
        if (!cancelled) setSetupRequired(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (user?.membership?.status === "pending") return <Navigate to="/setup" replace />;
  if (user) return <Navigate to="/" replace />;
  if (setupRequired) return <Navigate to="/setup" replace />;

  return (
    <AuthLayout mode={mode}>
      {mode === "signup" ? <SignupForm key="signup" /> : <LoginForm key="login" />}
    </AuthLayout>
  );
}
