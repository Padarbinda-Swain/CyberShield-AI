import { createContext, useContext, useEffect, useState } from "react";
import { api, getToken, setToken } from "./api.js";

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(!getToken());
  useEffect(() => {
    if (getToken()) api("/auth/me").then(setUser).catch(() => setToken(null)).finally(() => setReady(true));
    const out = () => setUser(null);
    window.addEventListener("cs-logout", out);
    return () => window.removeEventListener("cs-logout", out);
  }, []);
  const finish = (r) => { setToken(r.token); setUser(r.user); };
  const value = {
    user, ready,
    login: async (email, password) => finish(await api("/auth/login", { method: "POST", body: { email, password } })),
    register: async (name, email, password) => finish(await api("/auth/register", { method: "POST", body: { name, email, password } })),
    logout: () => { setToken(null); setUser(null); },
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
