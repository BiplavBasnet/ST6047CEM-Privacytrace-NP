import type { ReactNode } from "react";
import { useAuth } from "../context/AuthContext";

export default function RoleGate({
  permission,
  children,
  fallback = null,
}: {
  permission: string;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const { can } = useAuth();
  if (!can(permission)) {
    return <>{fallback}</>;
  }
  return <>{children}</>;
}
