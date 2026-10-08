import { useEffect, useState } from "react";
import { Link2, Mail, MessageSquareWarning, Globe, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";

export const VERDICT = {
  SAFE: { label: "Safe", color: "var(--safe)", Icon: ShieldCheck },
  SUSPICIOUS: { label: "Suspicious", color: "var(--warn)", Icon: ShieldAlert },
  HIGH_RISK: { label: "High risk", color: "var(--danger)", Icon: ShieldX },
};
export const TYPE_ICON = { url: Link2, website: Globe, message: MessageSquareWarning, email: Mail };
export const TYPE_LABEL = { url: "URL", website: "Website", message: "Message", email: "Email" };

export const Pill = ({ verdict }) => <span className={`pill ${verdict}`}>{VERDICT[verdict]?.label || verdict}</span>;
export const when = (iso) => new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

export function Gauge({ score, verdict }) {
  const [v, setV] = useState(0);
  useEffect(() => { const t = setTimeout(() => setV(score), 80); return () => clearTimeout(t); }, [score]);
  const color = VERDICT[verdict]?.color;
  const r = 120, c = Math.PI * r;
  return (
    <div className="gauge" role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg viewBox="0 0 300 170">
        <path d="M30 150 A120 120 0 0 1 270 150" fill="none" stroke="var(--line)" strokeWidth="18" strokeLinecap="round" />
        <path className="arc" d="M30 150 A120 120 0 0 1 270 150" fill="none" stroke={color} strokeWidth="18" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c - (c * v) / 100} style={{ filter: `drop-shadow(0 0 10px ${color})` }} />
        {[30, 60].map((t) => { const a = Math.PI - (t / 100) * Math.PI; return <line key={t} x1={150 + 100 * Math.cos(a)} y1={150 - 100 * Math.sin(a)} x2={150 + 138 * Math.cos(a)} y2={150 - 138 * Math.sin(a)} stroke="var(--ink)" strokeWidth="3" />; })}
      </svg>
      <div className="num"><b style={{ color }}>{score}</b><small>risk score out of 100</small></div>
    </div>
  );
}

export function Anatomy({ parts }) {
  if (!parts?.length) return null;
  const flagged = parts.filter((p) => p.flag && p.note);
  return (
    <div className="anat">
      <div className="mute" style={{ fontSize: 13, marginBottom: 6 }}>Address anatomy – flagged parts are underlined</div>
      <div className="bar">
        {parts.map((p, i) => (
          <span key={i} tabIndex={p.note ? 0 : -1} className={`seg ${p.kind} ${p.flag ? "flag" : ""}`}>{p.text}{p.flag && p.note && <span className="tip">{p.note}</span>}</span>
        ))}
      </div>
      {flagged.length > 0 && <div className="notes">{flagged.map((p, i) => <span key={i}>{p.note}</span>)}</div>}
    </div>
  );
}

export function Donut({ safe, suspicious, dangerous, size = 150 }) {
  const total = safe + suspicious + dangerous;
  const r = 52, c = 2 * Math.PI * r;
  let off = 0;
  const seg = [[safe, "var(--safe)"], [suspicious, "var(--warn)"], [dangerous, "var(--danger)"]];
  return (
    <svg width={size} height={size} viewBox="0 0 140 140" role="img" aria-label="Scan results split">
      <circle cx="70" cy="70" r={r} fill="none" stroke="var(--line)" strokeWidth="16" />
      {total > 0 && seg.map(([n, col], i) => {
        const len = (n / total) * c; const el = <circle key={i} cx="70" cy="70" r={r} fill="none" stroke={col} strokeWidth="16" strokeDasharray={`${Math.max(len - 2, 0)} ${c}`} strokeDashoffset={-off} transform="rotate(-90 70 70)" />; off += len; return el;
      })}
      <text x="70" y="68" textAnchor="middle" fill="var(--text)" style={{ font: "800 28px var(--display)" }}>{total}</text>
      <text x="70" y="86" textAnchor="middle" fill="var(--mute)" style={{ font: "12px var(--body)" }}>scans</text>
    </svg>
  );
}

export function Trend({ data }) {
  const max = Math.max(1, ...data.map((d) => d.safe + d.suspicious + d.dangerous));
  return (
    <>
      <div className="bars" role="img" aria-label="Scans over the last 14 days">
        {data.map((d) => (
          <div className="c" key={d.date} title={`${d.date}: ${d.safe} safe, ${d.suspicious} suspicious, ${d.dangerous} dangerous`}>
            {[["safe", "var(--safe)"], ["suspicious", "var(--warn)"], ["dangerous", "var(--danger)"]].map(([k, col]) => <i key={k} style={{ height: `${(d[k] / max) * 100}%`, background: col }} />)}
          </div>
        ))}
      </div>
      <div className="axis"><span>{data[0]?.date.slice(5)}</span><span>{data[data.length - 1]?.date.slice(5)}</span></div>
    </>
  );
}

export function HBars({ data, color = "var(--sonar)" }) {
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = Math.max(1, ...entries.map((e) => e[1]));
  if (!entries.length) return <div className="empty">Nothing to show yet.</div>;
  return entries.map(([k, v]) => (
    <div className="hbar" key={k}><div><span>{k}</span><b>{v}</b></div><div className="track"><i style={{ width: `${(v / max) * 100}%`, background: color }} /></div></div>
  ));
}

export function Radar({ type }) {
  const steps = { url: ["Reading the address structure", "Comparing against known brands", "Running the URL model", "Asking threat-intelligence feeds"],
    website: ["Resolving the domain", "Inspecting redirects and page forms", "Checking certificate and domain age", "Scoring the evidence"],
    message: ["Reading the message", "Looking for pressure and bait", "Running the language model", "Checking any links inside"],
    email: ["Parsing sender and headers", "Reading the body and links", "Checking attachments (never opened)", "Scoring the evidence"] }[type];
  const [i, setI] = useState(0);
  useEffect(() => { const t = setInterval(() => setI((x) => Math.min(x + 1, steps.length - 1)), 900); return () => clearInterval(t); }, []);
  return (
    <div className="panel radar" role="status" aria-live="polite">
      <div className="disc" />
      <div><h3 style={{ margin: 0 }}>Analyzing…</h3><p className="mute" style={{ marginTop: 6 }}>{steps[i]}</p></div>
    </div>
  );
}

export function Highlighted({ text, terms }) {
  const t = (terms || []).filter((x) => x && x.length > 2).sort((a, b) => b.length - a.length).map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (!t.length) return <>{text}</>;
  const parts = text.split(new RegExp(`(${t.join("|")})`, "gi"));
  return parts.map((p, i) => (i % 2 ? <mark key={i}>{p}</mark> : <span key={i}>{p}</span>));
}
