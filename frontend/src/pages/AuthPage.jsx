import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../auth.jsx";

export default function AuthPage({ mode }) {
  const { user, login, register } = useAuth();
  const nav = useNavigate(), loc = useLocation();
  const [f, setF] = useState({ name: "", email: "", password: "" });
  const [err, setErr] = useState(""), [busy, setBusy] = useState(false);
  const reg = mode === "register";
  if (user) return <Navigate to={loc.state?.from || "/dashboard"} replace />;
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const submit = async (e) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try { reg ? await register(f.name, f.email, f.password) : await login(f.email, f.password); nav(loc.state?.from || "/dashboard"); }
    catch (x) { setErr(x.message); } finally { setBusy(false); }
  };
  return (
    <div className="auth">
      <form className="box panel" onSubmit={submit}>
        <Link to="/" className="brand" style={{ color: "var(--text)", margin: "0 0 22px" }}><ShieldCheck color="var(--sonar)" size={26} />CyberShield<i>AI</i></Link>
        <h1>{reg ? "Create your account" : "Welcome back"}</h1>
        <p className="mute" style={{ marginBottom: 22 }}>{reg ? "Keep a private history of everything you check." : "Sign in to scan links, messages and emails."}</p>
        {err && <div className="err" role="alert">{err}</div>}
        {reg && <label className="field"><span>Your name</span><input className="input" required minLength={2} value={f.name} onChange={set("name")} autoComplete="name" /></label>}
        <label className="field"><span>Email</span><input className="input" type="email" required value={f.email} onChange={set("email")} autoComplete="email" /></label>
        <label className="field"><span>Password{reg && " (8+ characters, letters and numbers)"}</span><input className="input" type="password" required minLength={reg ? 8 : 1} value={f.password} onChange={set("password")} autoComplete={reg ? "new-password" : "current-password"} /></label>
        <button className="btn primary" style={{ width: "100%", justifyContent: "center" }} disabled={busy}>{busy ? "Please wait…" : reg ? "Create account" : "Sign in"}</button>
        <p className="mute" style={{ marginTop: 18, fontSize: 14 }}>{reg ? <>Already registered? <Link to="/login">Sign in</Link></> : <>New here? <Link to="/register">Create an account</Link></>}</p>
      </form>
    </div>
  );
}
