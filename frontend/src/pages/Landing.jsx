import { Link } from "react-router-dom";
import { ShieldCheck, Link2, MessageSquareWarning, Mail, Globe, TriangleAlert } from "lucide-react";

export default function Landing() {
  return (
    <div className="land">
      <nav>
        <div className="brand" style={{ margin: 0 }}><ShieldCheck color="var(--sonar)" size={28} />CyberShield<i>AI</i></div>
        <div style={{ display: "flex", gap: 10 }}><Link className="btn ghost" to="/login">Sign in</Link><Link className="btn primary" to="/register">Create free account</Link></div>
      </nav>
      <section className="hero">
        <div>
          <h1>Check it before you click it.</h1>
          <p className="lead">Paste a link, text message, email or website. CyberShield tells you if it is safe, suspicious or a scam, with a plain-language reason for every verdict.</p>
          <div className="cta"><Link className="btn primary" to="/register">Scan something now</Link><Link className="btn" to="/login">I already have an account</Link></div>
        </div>
        <div className="demo" aria-label="Example scan of a fake PayPal address">
          <div className="mute" style={{ fontSize: 13, marginBottom: 10 }}>Someone texts you this link:</div>
          <div className="urlbar"><span className="seg flag">http://</span><span className="seg flag">secure-paypa1-login</span><span className="seg domain">.com</span><span className="seg">/verify/account</span></div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 14, marginTop: 22 }}>
            <b style={{ font: "800 72px/1 var(--display)", letterSpacing: "-.05em", color: "var(--danger)" }}>92</b>
            <div><span className="pill HIGH_RISK">High risk</span><div className="mute" style={{ fontSize: 14, marginTop: 4 }}>Phishing · 94% confidence</div></div>
          </div>
          <ul>
            <li><TriangleAlert size={16} />“paypa1” uses the number 1 to imitate PayPal</li>
            <li><TriangleAlert size={16} />Login and verify keywords in the address</li>
            <li><TriangleAlert size={16} />No HTTPS, so anything you type can be read</li>
          </ul>
        </div>
      </section>
      <section className="strip">
        <div><Link2 size={22} /><h3>Links and websites</h3><p>Address structure, brand look-alikes, domain age, certificates, redirects and live reputation feeds.</p></div>
        <div><MessageSquareWarning size={22} /><h3>SMS and chat</h3><p>Spots banking, delivery, lottery, job, investment and OTP scams by how they pressure you.</p></div>
        <div><Mail size={22} /><h3>Emails</h3><p>Paste text or upload an .eml. Sender spoofing, hidden links and risky attachments are checked, never opened.</p></div>
        <div><Globe size={22} /><h3>Explained, not guessed</h3><p>Every score shows the evidence behind it and what to do next. Your history stays private to you.</p></div>
      </section>
      <div className="foot">CyberShield AI · Final-year project · Machine learning, NLP, threat intelligence and cloud security</div>
    </div>
  );
}
