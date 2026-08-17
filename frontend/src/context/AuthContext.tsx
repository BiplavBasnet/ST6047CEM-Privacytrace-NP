import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  authApi,
  clearAuthToken,
  getAuthToken,
  setAuthToken,
  setOnSessionExpired,
  type AuthUser,
} from "../api/authClient";
import { hasPermission } from "../utils/permissions";

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const loadMe = useCallback(async () => {
    const token = getAuthToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      const me = await authApi.me();
      setUser(me);
    } catch {
      clearAuthToken();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMe();
  }, [loadMe]);

  useEffect(() => {
    setOnSessionExpired(() => {
      setUser(null);
    });
    return () => setOnSessionExpired(null);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const response = await authApi.login(email, password);
    setAuthToken(response.access_token);
    setUser(response.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      if (getAuthToken()) {
        await authApi.logout();
      }
    } catch {
      /* still clear local session */
    } finally {
      clearAuthToken();
      setUser(null);
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      login,
      logout,
      refresh: loadMe,
      can: (permission: string) => {
        if (!user?.membership || user.membership.status !== "active") return false;
        return hasPermission(user.membership.role || user.role, permission);
      },
    }),
    [user, loading, login, logout, loadMe],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
