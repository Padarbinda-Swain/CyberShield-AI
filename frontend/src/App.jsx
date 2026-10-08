import { Navigate, NavLink, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { History, LayoutDashboard, LogOut, ScanSearch, ShieldCheck, Gauge } from "lucide-react";
import { useAuth } from "./auth.jsx";
import Landing from "./pages/Landing.jsx";
import AuthPage from "./pages/AuthPage.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Scan from "./pages/Scan.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import Admin from "./pages/Admin.jsx";

function Shell() {
  const { user, ready, logout } = useAuth();
  const loc = useLocation();
  if (!ready) return null;
  if (!user) return <Navigate to="/login" state={{ from: loc.pathname }} replace />;
  return (
    <div className="shell">
      <aside className="side">
        <div className="brand"><ShieldCheck color="var(--sonar)" size={26} />CyberShield<i>AI</i></div>
        <nav className="nav">
          <NavLink to="/dashboard"><LayoutDashboard size={19} />Dashboard</NavLink>
          <NavLink to="/scan"><ScanSearch size={19} />New scan</NavLink>
          <NavLink to="/history"><History size={19} />History</NavLink>
          {user.role === "admin" && <NavLink to="/admin"><Gauge size={19} />Admin</NavLink>}
        </nav>
        <div className="who"><div style={{ fontWeight: 600 }}>{user.name}</div><div className="mute" style={{ wordBreak: "break-all" }}>{user.email}</div>
          <button className="btn ghost sm" style={{ marginTop: 10, padding: "6px 0" }} onClick={logout}><LogOut size={15} />Sign out</button></div>
      </aside>
      <main className="main"><Outlet /></main>
    </div>
  );
}

export default function App() {
  const { user } = useAuth();
  return (
    <Routes>
      <Route path="/" element={user ? <Navigate to="/dashboard" replace /> : <Landing />} />
      <Route path="/login" element={<AuthPage mode="login" />} />
      <Route path="/register" element={<AuthPage mode="register" />} />
      <Route element={<Shell />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/scan/:id" element={<ScanDetail />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/admin" element={user?.role === "admin" ? <Admin /> : <Navigate to="/dashboard" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
