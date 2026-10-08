const $ = (id) => document.getElementById(id);
const COLORS = { SAFE: "#3DDC97", SUSPICIOUS: "#FFB224", HIGH_RISK: "#FF5A5F" };
const LABEL = { SAFE: "Safe", SUSPICIOUS: "Suspicious", HIGH_RISK: "High risk" };

async function render() {
  const s = await chrome.storage.local.get({ api: "http://localhost:8000", token: null, enabled: true });
  $("api").value = s.api; $("en").checked = s.enabled;
  $("login").hidden = !!s.token; $("main").hidden = !s.token;
  if (!s.token) return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  $("url").textContent = tab?.url?.slice(0, 80) || "";
  if (!/^https?:/.test(tab?.url || "")) { $("score").textContent = "–"; $("verdict").textContent = "This page type is not scanned."; return; }
  const r = await chrome.runtime.sendMessage({ type: "check-now", url: tab.url });
  if (r.error) { $("score").textContent = "–"; $("verdict").textContent = r.error === "signin" ? "Please sign in again." : "CyberShield server is unreachable."; return; }
  $("score").textContent = r.risk_score; $("score").style.color = COLORS[r.verdict];
  $("verdict").innerHTML = `<b style="color:${COLORS[r.verdict]}">${LABEL[r.verdict]}</b> · ${r.threat_type} · ${r.confidence}% confidence`;
  $("why").replaceChildren(...r.reasons.map((t) => Object.assign(document.createElement("li"), { textContent: t })));
}
$("go").onclick = async () => {
  const api = $("api").value.replace(/\/$/, "");
  try {
    const res = await fetch(`${api}/api/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: $("email").value, password: $("pw").value }) });
    const j = await res.json();
    if (!res.ok) throw new Error(j.detail || "Sign-in failed");
    await chrome.storage.local.set({ api, token: j.token }); render();
  } catch (e) { $("err").textContent = e.message; }
};
$("en").onchange = () => chrome.storage.local.set({ enabled: $("en").checked });
$("out").onclick = async () => { await chrome.storage.local.set({ token: null }); render(); };
render();
