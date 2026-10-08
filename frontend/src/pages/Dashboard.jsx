import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Lightbulb, ScanSearch } from "lucide-react";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import { Donut, HBars, Pill, TYPE_ICON, TYPE_LABEL, Trend, when } from "../components/ui.jsx";

export default function Dashboard() {
  const { user } = useAuth(), nav = useNavigate();
  const [d, setD] = useState(null), [err, setErr] = useState(""), [q, setQ] = useState("");
  useEffect(() => { api("/dashboard").then(setD).catch((e) => setErr(e.message)); }, []);
  const go = (e) => { e.preventDefault(); if (q.trim()) nav("/scan", { state: { value: q.trim(), mode: /\s/.test(q.trim()) ? "message" : "url" } }); };
  return (
    <>
      <div className="page-h"><div><h1>Hello, {user.name.split(" ")[0]}</h1><p>Here is what CyberShield has checked for you.</p></div></div>
      <form className="quick" onSubmit={go}>
        <ScanSearch size={20} color="var(--sonar)" />
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Paste a link or a message to check it now" aria-label="Quick check" />
        <button className="btn primary">Analyze</button>
      </form>
      {err && <div className="err" style={{ marginTop: 20 }}>{err}</div>}
      {d && <>
        <div className="ledger" style={{ marginTop: 26 }}>
          <div><small><span className="dot sonar" />Total scans</small><b>{d.total}</b></div>
          <div><small><span className="dot safe" />Safe</small><b className="safe">{d.safe}</b></div>
          <div><small><span className="dot warn" />Suspicious</small><b className="warn">{d.suspicious}</b></div>
          <div><small><span className="dot danger" />Dangerous</small><b className="danger">{d.dangerous}</b></div>
        </div>
        <div className="grid3">
          <section className="panel"><h3>Last 14 days</h3><Trend data={d.trend} /></section>
          <section className="panel"><h3>Results mix</h3>
            <div className="donut-wrap"><Donut safe={d.safe} suspicious={d.suspicious} dangerous={d.dangerous} />
              <div className="legend"><div><span className="dot safe" />Safe<b>{d.safe}</b></div><div><span className="dot warn" />Suspicious<b>{d.suspicious}</b></div><div><span className="dot danger" />Dangerous<b>{d.dangerous}</b></div>
                <div className="mute" style={{ fontSize: 13, marginTop: 10 }}>Average risk score: {d.avg_risk}</div></div></div></section>
        </div>
        <div className="grid3">
          <section className="panel"><div style={{ display: "flex", justifyContent: "space-between" }}><h3>Recent scans</h3><Link to="/history" style={{ fontSize: 14 }}>See all</Link></div>
            {d.recent.length === 0 ? <div className="empty">No scans yet. <Link to="/scan">Check your first link or message</Link>.</div> :
              <div className="rows">{d.recent.map((s) => { const I = TYPE_ICON[s.input_type]; return (
                <Link className="row" to={`/scan/${s.id}`} key={s.id}><span className="ic"><I size={17} /></span>
                  <span className="t"><span className={s.input_type === "url" || s.input_type === "website" ? "mono" : ""}>{s.input.replace(/\s+/g, " ").slice(0, 70)}</span><small>{TYPE_LABEL[s.input_type]} · {s.threat_type} · {when(s.created_at)}</small></span>
                  <span className="hide-sm"><Pill verdict={s.verdict} /></span><span className="score">{s.risk_score}</span></Link>); })}</div>}
          </section>
          <div style={{ display: "grid", gap: 20, alignContent: "start" }}>
            <section className="panel"><h3>Threat categories</h3>{Object.keys(d.threats).length ? <HBars data={d.threats} color="var(--danger)" /> : <div className="empty">No threats found yet.</div>}</section>
            <section className="panel"><h3><Lightbulb size={17} style={{ verticalAlign: -2, color: "var(--warn)" }} /> Stay safe</h3>
              <ul className="actions" style={{ padding: 0 }}>{d.tips.slice(0, 3).map((t) => <li key={t}><span>{t}</span></li>)}</ul></section>
          </div>
        </div>
      </>}
    </>
  );
}
