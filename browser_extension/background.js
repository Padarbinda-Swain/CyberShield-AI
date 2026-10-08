// Checks each visited page against the CyberShield cloud API and warns (never blocks) on dangerous sites.
const DEFAULT_API = "http://localhost:8000";
const CACHE_MS = 10 * 60 * 1000;
const WARN_MIN_CONFIDENCE = 75; // warn only when the engine is confident, to limit false alarms
const cache = new Map();

async function settings() { return chrome.storage.local.get({ api: DEFAULT_API, token: null, enabled: true }); }

async function check(url) {
  const hit = cache.get(url);
  if (hit && Date.now() - hit.t < CACHE_MS) return hit.r;
  const { api, token } = await settings();
  if (!token) return { error: "signin" };
  const res = await fetch(`${api}/api/extension/check`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ url }) });
  if (res.status === 401) { await chrome.storage.local.set({ token: null }); return { error: "signin" }; }
  if (!res.ok) return { error: "unavailable" };
  const r = await res.json();
  cache.set(url, { r, t: Date.now() });
  return r;
}

const COLORS = { SAFE: "#3DDC97", SUSPICIOUS: "#FFB224", HIGH_RISK: "#FF5A5F" };
async function handle(tabId, url) {
  if (!/^https?:\/\//.test(url)) return;
  const { enabled } = await settings();
  if (!enabled) return;
  try {
    const r = await check(url);
    if (r.error) { chrome.action.setBadgeText({ tabId, text: r.error === "signin" ? "?" : "" }); return; }
    chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[r.verdict] });
    chrome.action.setBadgeText({ tabId, text: r.verdict === "SAFE" ? "OK" : String(r.risk_score) });
    chrome.storage.session.set({ [`tab${tabId}`]: { url, ...r } });
    if (r.verdict === "HIGH_RISK" && r.confidence >= WARN_MIN_CONFIDENCE) chrome.tabs.sendMessage(tabId, { type: "cybershield-warn", result: r }).catch(() => {});
  } catch { chrome.action.setBadgeText({ tabId, text: "" }); }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => { if (info.status === "complete" && tab.url) handle(tabId, tab.url); });
chrome.runtime.onMessage.addListener((msg, _s, send) => {
  if (msg.type === "check-now") { check(msg.url).then(send); return true; }
});
