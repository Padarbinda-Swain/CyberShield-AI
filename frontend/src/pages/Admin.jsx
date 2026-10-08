import { useEffect, useState } from "react";
import { api } from "../api.js";
import { HBars, Trend, when } from "../components/ui.jsx";

const pct = (x) => `${(x * 100).toFixed(1)}%`;
function Models({ title, m }) {
  if (!m) return null;
  const best = m.results.find((r) => r.model === m.best);
  return (
    <section className="panel" style={{ marginTop: 20 }}>
      <h3>{title} <span className="mute" style={{ fontSize: 14, fontWeight: 400 }}>· {m.samples.toLocaleString()} training samples · best: {m.best}</span></h3>
      <div style={{ overflowX: "auto" }}><table><thead><tr><th>Model</th><th className="n">Accuracy</th><th className="n">Precision</th><th className="n">Recall</th><th className="n">F1</th><th className="n">ROC-AUC</th></tr></thead>
        <tbody>{m.results.map((r) => <tr key={r.model} style={r.model === m.best ? { background: "rgba(76,201,240,.08)" } : {}}><td>{r.model}{r.model === m.best && <span className="pill SAFE" style={{ marginLeft: 8 }}>deployed</span>}</td><td className="n">{pct(r.accuracy)}</td><td className="n">{pct(r.precision)}</td><td className="n">{pct(r.recall)}</td><td className="n">{pct(r.f1)}</td><td className="n">{r.roc_auc.toFixed(3)}</td></tr>)}</tbody></table></div>
      {best && <details><summary>Confusion matrix – {best.model}</summary><div className="in" style={{ overflowX: "auto" }}><table className="cm"><thead><tr><th>actual ↓ / predicted →</th>{m.classes.map((c) => <th key={c} style={{ textAlign: "center" }}>{c.replace(/_/g, " ")}</th>)}</tr></thead>
        <tbody>{best.confusion_matrix.map((row, i) => <tr key={i}><td style={{ textAlign: "left", fontFamily: "var(--body)" }}>{m.classes[i].replace(/_/g, " ")}</td>{row.map((v, j) => <td key={j} style={{ background: `rgba(76,201,240,${i === j ? Math.min(0.5, v / 400) : v ? 0.18 : 0})` }}>{v}</td>)}</tr>)}</tbody></table></div></details>}
    </section>
  );
}

export default function Admin() {
  const [d, setD] = useState(null), [err, setErr] = useState("");
  useEffect(() => { api("/admin/overview").then(setD).catch((e) => setErr(e.message)); }, []);
  if (err) return <div className="err">{err}</div>;
  if (!d) return <div className="empty">Loading…</div>;
  const s = d.system, up = Math.floor(s.uptime_seconds / 60);
  const ok = (v) => <span className={v ? "safe" : "warn"}>● {v ? "Online" : "Not configured"}</span>;
  return (
    <>
      <div className="page-h"><div><h1>Admin overview</h1><p>Platform-wide statistics. Message contents and personal details are never shown here.</p></div></div>
      <div className="ledger">
        <div><small><span className="dot sonar" />Users</small><b>{d.users}</b></div><div><small><span className="dot sonar" />Total scans</small><b>{d.total}</b></div>
        <div><small><span className="dot danger" />High-risk found</small><b className="danger">{d.dangerous}</b></div><div><small><span className="dot warn" />Suspicious</small><b className="warn">{d.suspicious}</b></div>
      </div>
      <div className="grid3">
        <section className="panel"><h3>Threat trend · 14 days</h3><Trend data={d.trend} /></section>
        <section className="panel"><h3>Most common attack types</h3><HBars data={d.threats} color="var(--danger)" /></section>
      </div>
      <div className="grid2">
        <section className="panel"><h3>Recent high-risk detections</h3>
          {d.recent_malicious.length === 0 ? <div className="empty">None yet.</div> : <div className="rows">{d.recent_malicious.map((x, i) => <div className="row" style={{ gridTemplateColumns: "1fr auto auto" }} key={i}><span className="t"><span className="mono">{x.input}</span><small>{x.threat_type} · {when(x.created_at)}</small></span><span className="hide-sm mute">{x.input_type}</span><span className="score danger">{x.risk_score}</span></div>)}</div>}</section>
        <section className="panel"><h3>System status</h3>
          <div className="status"><span>API</span><span className="safe">● Online · up {up} min</span></div>
          <div className="status"><span>Database</span><span className="safe">● {s.database === "mongodb" ? "MongoDB Atlas" : "Local file store"}</span></div>
          <div className="status"><span>URL model</span>{ok(s.url_model)}</div><div className="status"><span>Text model</span>{ok(s.text_model)}</div>
          <div className="status"><span>Live domain checks</span>{ok(s.live_checks)}</div>
          <div className="status"><span>Local blocklist</span><span className="mute">{s.blocklist_entries} entries</span></div>
          {s.threat_intel.map((t) => <div className="status" key={t.name}><span>{t.name}</span>{ok(t.configured)}</div>)}</section>
      </div>
      <Models title="URL classifier" m={d.models.url} />
      <Models title="Social-engineering classifier" m={d.models.text} />
    </>
  );
}
