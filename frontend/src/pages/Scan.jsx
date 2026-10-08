import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Globe, Link2, Mail, MessageSquareWarning, Paperclip, ScanSearch } from "lucide-react";
import { api } from "../api.js";
import { Radar } from "../components/ui.jsx";

const MODES = {
  url: { label: "URL", icon: Link2, ph: "paypa1-login.com/verify", hint: "Paste any link. It is analysed, never opened by our servers.", single: true, samples: ["paypal.com", "paypa1-login.com", "g00gle-security.com", "amaz0n-support.com", "https://github.com"] },
  message: { label: "Message / SMS", icon: MessageSquareWarning, ph: "Paste the SMS or chat message here…", hint: "Works for SMS, WhatsApp and chat messages.", samples: ["Your bank account will be blocked today. Verify immediately using this link http://hdfc-update.top/kyc", "Congratulations! You won Rs 25,00,000 in the lucky draw. Share the OTP to claim your prize.", "Hey, are we still meeting for lunch tomorrow at 1?"] },
  email: { label: "Email", icon: Mail, ph: "Paste the email text, or the full raw source with headers…", hint: "For the best result include headers (From, Reply-To, Authentication-Results) or upload the .eml file.", file: true,
    samples: ["From: PayPal Support <help@paypa1-secure.xyz>\nReply-To: scam@gmail.com\nSubject: Your account is limited\nAuthentication-Results: mx; spf=fail; dkim=none\n\nDear customer, verify your password within 24 hours at http://paypa1-secure.xyz/login or your account will be suspended."] },
  website: { label: "Website", icon: Globe, ph: "https://example.com", hint: "Adds redirect, certificate, domain-age and page-form checks (read-only, nothing is executed).", single: true, samples: ["https://github.com", "http://example.com"] },
};
const API = { url: "/scan/url", website: "/scan/website", message: "/scan/message", email: "/scan/email" };

export default function Scan() {
  const nav = useNavigate(), loc = useLocation();
  const [mode, setMode] = useState(loc.state?.mode || "url");
  const [text, setText] = useState(loc.state?.value || "");
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false), [err, setErr] = useState("");
  const auto = useRef(false);
  const m = MODES[mode];

  const run = async (value = text, md = mode) => {
    setErr(""); setBusy(true);
    try {
      let r;
      if (file && md === "email") { const fd = new FormData(); fd.append("file", file); r = await api("/scan/email/upload", { method: "POST", form: fd }); }
      else r = await api(API[md], { method: "POST", body: md === "url" || md === "website" ? { url: value.trim() } : { text: value } });
      nav(`/scan/${r.id}`, { state: { result: r } });
    } catch (e) { setErr(e.message); setBusy(false); }
  };
  useEffect(() => { if (loc.state?.value && !auto.current) { auto.current = true; run(loc.state.value, loc.state.mode || "url"); } }, []);

  return (
    <>
      <div className="page-h"><div><h1>What do you want to check?</h1><p>{m.hint}</p></div></div>
      <div className="tabs" role="tablist">
        {Object.entries(MODES).map(([k, v]) => <button key={k} role="tab" aria-selected={mode === k} className={mode === k ? "on" : ""} onClick={() => { setMode(k); setText(""); setFile(null); setErr(""); }}><v.icon size={17} />{v.label}</button>)}
      </div>
      {busy ? <Radar type={mode} /> : (
        <form className="panel" onSubmit={(e) => { e.preventDefault(); run(); }}>
          {err && <div className="err" role="alert">{err}</div>}
          {m.single
            ? <input className="input mono" style={{ fontSize: 16 }} value={text} onChange={(e) => setText(e.target.value)} placeholder={m.ph} required aria-label={m.label} autoFocus spellCheck="false" />
            : <textarea className="textarea" value={text} onChange={(e) => setText(e.target.value)} placeholder={m.ph} required={!file} aria-label={m.label} maxLength={20000} />}
          {m.file && (
            <label className="drop"><Paperclip size={18} />{file ? `${file.name} – ready to analyze` : "Or upload an .eml / .txt email file (max 1 MB)"}
              <input type="file" accept=".eml,.txt" onChange={(e) => setFile(e.target.files[0] || null)} /></label>
          )}
          <div className="chips"><span className="dim" style={{ fontSize: 13 }}>Try an example:</span>
            {m.samples.map((s) => <button type="button" className="chip" key={s} onClick={() => { setText(s); setFile(null); }}>{s.length > 38 ? s.slice(0, 36).replace(/\n/g, " ") + "…" : s}</button>)}</div>
          <div style={{ marginTop: 20 }}><button className="btn primary" disabled={!text.trim() && !file}><ScanSearch size={18} />Analyze</button></div>
        </form>
      )}
    </>
  );
}
