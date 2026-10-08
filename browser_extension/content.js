// Shows a dismissible warning banner inside an isolated shadow DOM. The page is never blocked or modified otherwise.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "cybershield-warn" || document.getElementById("cybershield-warning")) return;
  const host = document.createElement("div");
  host.id = "cybershield-warning";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `.b{all:initial;position:fixed;z-index:2147483647;top:0;left:0;right:0;display:flex;gap:14px;align-items:center;padding:14px 20px;
    background:#2a0d12;border-bottom:3px solid #FF5A5F;color:#fff;font:15px/1.4 system-ui,sans-serif;box-shadow:0 8px 30px rgba(0,0,0,.45)}
    b{color:#FF8A8E}small{display:block;color:#f0b4b7;margin-top:2px}.x{margin-left:auto;background:transparent;color:#fff;border:1px solid #ffffff55;border-radius:99px;padding:6px 14px;cursor:pointer;font:inherit}`;
  const bar = document.createElement("div");
  bar.className = "b";
  const text = document.createElement("div");
  const strong = document.createElement("b");
  strong.textContent = "⚠️ CyberShield AI detected that this website may be unsafe.";
  const small = document.createElement("small");
  small.textContent = `Avoid entering passwords or financial information. Risk ${msg.result.risk_score}/100 · ${msg.result.threat_type}` + (msg.result.reasons?.[0] ? ` · ${msg.result.reasons[0]}` : "");
  text.append(strong, small);
  const btn = document.createElement("button");
  btn.className = "x"; btn.textContent = "Dismiss";
  btn.onclick = () => host.remove();
  bar.append(text, btn);
  root.append(style, bar);
  document.documentElement.append(host);
});
