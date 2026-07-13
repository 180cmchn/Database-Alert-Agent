import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

const SESSION_KEY = "db-sentinel.admin-token";

interface AdminAuthValue {
  token: string;
  unlocked: boolean;
  unlock: (token: string) => void;
  lock: () => void;
}

const AdminAuthContext = createContext<AdminAuthValue | null>(null);

export function AdminAuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState(() => sessionStorage.getItem(SESSION_KEY) || "");

  const unlock = useCallback((nextToken: string) => {
    const trimmed = nextToken.trim();
    sessionStorage.setItem(SESSION_KEY, trimmed);
    setToken(trimmed);
  }, []);

  const lock = useCallback(() => {
    sessionStorage.removeItem(SESSION_KEY);
    setToken("");
  }, []);

  const value = useMemo(
    () => ({ token, unlocked: Boolean(token), unlock, lock }),
    [lock, token, unlock],
  );

  return <AdminAuthContext.Provider value={value}>{children}</AdminAuthContext.Provider>;
}

export function useAdminAuth(): AdminAuthValue {
  const value = useContext(AdminAuthContext);
  if (!value) throw new Error("useAdminAuth must be used inside AdminAuthProvider");
  return value;
}
