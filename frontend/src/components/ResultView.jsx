import { Fragment } from "react";
import { ArrowRight, CheckCircle2, ShieldCheck } from "lucide-react";
import { Anatomy, Gauge, Highlighted, Pill, TYPE_LABEL, VERDICT, when } from "./ui.jsx";

const sigColor = (s) => (s > 60 ? "var(--danger)" : s > 30 ? "var(--warn)" : "var(--safe)");
const headline = { SAFE: "Looks safe", SUSPICIOUS: "Be careful with this", HIGH_RISK: "Do not trust this" };

export default function ResultView({ r }) {
  const d = r.details || {};
  const isText = r.input_type === "message" || r.input_type === "email";
  return (
    <div>
      <section className="panel">
        <div className="verdict">
          <Gauge score={r.risk_score} verdict={r.verdict} />
          <div>
            <Pill verdict={r.verdict} />
            <h1 style={{ color: VERDICT[r.verdict].color }}>{headline[r.verdict]}</h1>
            <div style={{ fontSize: 19 }}>{r.threat_type}</div>
            <div className="meta">
              <div><small>Confidence</small><b>{r.confidence}%</b></div>
              <div><small>Checked</small><b>{TYPE_LABEL[r.input_type]}</b></div>
              {r.created_at && <div><small>When</small><b>{when(r.created_at)}</b></div>}
            </div>
            {!isText && <div className="mono mute" style={{ marginTop: 14, wordBreak: "break-all" }}>{r.input}</div>}
          </div>
        </div>
        {!isText && <Anatomy parts={d.anatomy} />}
        {isText && <div className="msg"><Highlighted text={r.input} terms={d.highlights} /></div>}
      </section>

      <div className="grid2">
        <section className="panel">
          <h3>Why we think so</h3>
          <ul className="reasons" style={{ padding: 0 }}>
            {r.reasons.map((x, i) => <li key={i}><span className={`sev ${x.severity}`} /><div>{x.text}<small>{{ rules: "Security rules", ml: "Machine learning", nlp: "Language analysis", domain: "Domain analysis", website: "Website inspection", threat_intel: "Threat intelligence", links: "Embedded links", email: "Email analysis" }[x.source] || x.source}</small></div></li>)}
          </ul>
        </section>
        <section className="panel">
          <h3>What to do next</h3>
          <ul className="actions" style={{ padding: 0 }}>
            {r.recommendations.map((x, i) => <li key={i}>{r.verdict === "SAFE" ? <CheckCircle2 size={18} /> : <ArrowRight size={18} />}<span>{x}</span></li>)}
          </ul>
        </section>
      </div>

      <section className="panel" style={{ marginTop: 20 }}>
        <h3>How the score was built</h3>
        <div className="sigs">
          {r.signals.map((s) => (
            <div className="s" key={s.name}>
              <div><span>{s.name}</span><span className="mono mute">{s.score}/100 · weight {s.weight}</span></div>
              <div className="track"><i style={{ width: `${s.score}%`, background: sigColor(s.score) }} /></div>
            </div>
          ))}
        </div>
        {r.adjustments?.length > 0 && <p className="mute" style={{ fontSize: 14 }}><ShieldCheck size={14} style={{ verticalAlign: -2 }} /> Safety rule applied: {r.adjustments.join("; ")}.</p>}
        <p className="dim" style={{ fontSize: 13, marginTop: 10 }}>Several independent signals are blended, so no single model or feed decides alone. No scan can guarantee safety.</p>
      </section>

      <details>
        <summary>Technical details</summary>
        <div className="in">
          {d.threat_intel && (
            <><h4 className="mute" style={{ margin: "12px 0 6px" }}>Threat-intelligence sources</h4>
              <table><thead><tr><th>Source</th><th>Result</th></tr></thead><tbody>
                {d.threat_intel.sources.map((s) => <tr key={s.source}><td>{s.source}</td><td className={s.malicious ? "danger" : "mute"}>{s.status === "skipped" ? `Not configured – ${s.detail}` : s.detail}</td></tr>)}
              </tbody></table></>
          )}
          {d.live?.enabled && (
            <><h4 className="mute" style={{ margin: "18px 0 6px" }}>Live domain checks</h4>
              <dl className="kv">
                {d.live.dns && <><dt>DNS</dt><dd>{d.live.dns.resolves ? (d.live.dns.ips?.join(", ") || "resolves") : "does not resolve"}</dd></>}
                {d.live.domain?.known && <><dt>Domain age</dt><dd>{d.live.domain.age_days} days (registered {d.live.domain.registered})</dd></>}
                {d.live.tls && <><dt>SSL certificate</dt><dd>{d.live.tls.valid ? `Valid · ${d.live.tls.issuer} · expires ${d.live.tls.expires}` : d.live.tls.error || "unavailable"}</dd></>}
                {d.live.page?.final_url && <><dt>Final address</dt><dd className="mono">{d.live.page.final_url} ({d.live.page.redirects} redirects)</dd></>}
                {d.live.page?.title && <><dt>Page title</dt><dd>{d.live.page.title}</dd></>}
                {d.live.page?.security_headers && <><dt>Security headers</dt><dd>{Object.entries(d.live.page.security_headers).map(([k, v]) => <span key={k} className={v ? "safe" : "danger"} style={{ marginRight: 12 }}>{v ? "✓" : "✗"} {k}</span>)}</dd></>}
              </dl></>
          )}
          {d.ml?.probs && (<><h4 className="mute" style={{ margin: "18px 0 6px" }}>Model probabilities ({d.ml.model})</h4><dl className="kv">{Object.entries(d.ml.probs).map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{(v * 100).toFixed(1)}%</dd></Fragment>)}</dl></>)}
          {d.top_terms?.length > 0 && (<><h4 className="mute" style={{ margin: "18px 0 6px" }}>Words that pushed the decision</h4><p>{d.top_terms.map((t) => <mark key={t.term} style={{ marginRight: 8 }}>{t.term}</mark>)}</p></>)}
          {d.links?.length > 0 && (<><h4 className="mute" style={{ margin: "18px 0 6px" }}>Links found</h4><table><tbody>{d.links.map((l) => <tr key={l.url}><td className="mono" style={{ wordBreak: "break-all" }}>{l.url}</td><td><Pill verdict={l.verdict} /></td><td className="n">{l.risk_score}</td></tr>)}</tbody></table></>)}
          {d.email && (<><h4 className="mute" style={{ margin: "18px 0 6px" }}>Email headers</h4><dl className="kv">
            <dt>From</dt><dd>{d.email.from}</dd><dt>Subject</dt><dd>{d.email.subject}</dd>
            {d.email.reply_to && <><dt>Reply-To</dt><dd>{d.email.reply_to}</dd></>}
            <dt>SPF / DKIM / DMARC</dt><dd>{Object.values(d.email.auth || {}).join(" / ")}</dd>
            <dt>Attachments</dt><dd>{d.email.attachments?.length ? d.email.attachments.map((a) => a.name).join(", ") : "none"}</dd></dl></>)}
        </div>
      </details>
    </div>
  );
}
