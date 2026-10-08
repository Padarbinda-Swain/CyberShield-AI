import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { Pill, TYPE_ICON, TYPE_LABEL, when } from "../components/ui.jsx";

const SCORE_COLOR = (v) => (v === "SAFE" ? "var(--safe)" : v === "SUSPICIOUS" ? "var(--warn)" : "var(--danger)");

export default function HistoryPage() {
  const [data, setData] = useState(null), [verdict, setVerdict] = useState(""), [type, setType] = useState(""), [skip, setSkip] = useState(0), [err, setErr] = useState("");
  const LIM = 15;
  useEffect(() => {
    const q = new URLSearchParams({ limit: LIM, skip, ...(verdict && { verdict }), ...(type && { input_type: type }) });
    api(`/scans?${q}`).then(setData).catch((e) => setErr(e.message));
  }, [verdict, type, skip]);
  const Sel = ({ v, set, opts, label }) => <select aria-label={label} className="input" style={{ width: "auto", padding: "8px 14px" }} value={v} onChange={(e) => { set(e.target.value); setSkip(0); }}>{opts.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>;
  return (
    <>
      <div className="page-h"><div><h1>Scan history</h1><p>Every check you have run, newest first. Only you can see these.</p></div>
        <div style={{ display: "flex", gap: 8 }}>
          <Sel v={type} set={setType} label="Filter by type" opts={[["", "All types"], ["url", "URL"], ["website", "Website"], ["message", "Message"], ["email", "Email"]]} />
          <Sel v={verdict} set={setVerdict} label="Filter by result" opts={[["", "Any result"], ["SAFE", "Safe"], ["SUSPICIOUS", "Suspicious"], ["HIGH_RISK", "High risk"]]} /></div></div>
      <section className="panel">
        {err && <div className="err">{err}</div>}
        {!data ? <div className="empty">Loading…</div> : data.items.length === 0 ? <div className="empty">No scans match. <Link to="/scan">Run your first scan</Link>.</div> : (
          <div className="rows">{data.items.map((s) => { const I = TYPE_ICON[s.input_type]; return (
            <Link className="row" to={`/scan/${s.id}`} key={s.id}>
              <span className="ic"><I size={17} /></span>
              <span className="t"><span className={s.input_type === "url" || s.input_type === "website" ? "mono" : ""}>{s.input.replace(/\s+/g, " ").slice(0, 90)}</span><small>{TYPE_LABEL[s.input_type]} · {s.threat_type} · {when(s.created_at)}</small></span>
              <span className="hide-sm"><Pill verdict={s.verdict} /></span>
              <span className="score" style={{ color: SCORE_COLOR(s.verdict) }}>{s.risk_score}</span>
            </Link>); })}</div>
        )}
        {data && data.total > LIM && (
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 16, alignItems: "center" }}>
            <button className="btn sm" disabled={skip === 0} onClick={() => setSkip(Math.max(0, skip - LIM))}>Newer</button>
            <span className="mute" style={{ fontSize: 13 }}>{skip + 1}–{Math.min(skip + LIM, data.total)} of {data.total}</span>
            <button className="btn sm" disabled={skip + LIM >= data.total} onClick={() => setSkip(skip + LIM)}>Older</button></div>)}
      </section>
    </>
  );
}
