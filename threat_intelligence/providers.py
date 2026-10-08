"""Threat-intelligence connectors. Every provider degrades gracefully (status=skipped) without an API key
so the platform works offline; several independent signals are combined by the risk engine."""
from __future__ import annotations
import asyncio, base64, os, pathlib
import httpx

BLOCKLIST = pathlib.Path(__file__).parent / "local_blocklist.txt"
TIMEOUT = float(os.getenv("TI_TIMEOUT", "6"))


def _result(source, status, malicious=None, score=0, detail="", trusted=True):
    return {"source": source, "status": status, "malicious": malicious, "score": score, "detail": detail, "trusted": trusted}


async def local_blocklist(url: str, host: str):
    if not BLOCKLIST.exists():
        return _result("Local blocklist", "skipped", detail="No blocklist file")
    entries = {l.strip().lower() for l in BLOCKLIST.read_text().splitlines() if l.strip() and not l.startswith("#")}
    hit = host.lower() in entries or any(host.lower().endswith("." + e) for e in entries)
    return _result("Local blocklist", "ok", hit, 95 if hit else 0, "Host is on the internal blocklist" if hit else "Not listed")


async def urlhaus(client: httpx.AsyncClient, url: str, host: str):
    key = os.getenv("URLHAUS_AUTH_KEY")
    if not key:
        return _result("URLhaus", "skipped", detail="Set URLHAUS_AUTH_KEY to enable")
    r = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": key})
    j = r.json()
    if j.get("query_status") == "ok":
        return _result("URLhaus", "ok", True, 95, f"Listed in URLhaus ({j.get('threat', 'malware')}, status {j.get('url_status')})")
    return _result("URLhaus", "ok", False, 0, "Not listed in URLhaus")


async def virustotal(client: httpx.AsyncClient, url: str, host: str):
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return _result("VirusTotal", "skipped", detail="Set VIRUSTOTAL_API_KEY to enable")
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = await client.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": key})
    if r.status_code == 404:
        return _result("VirusTotal", "ok", None, 0, "URL not previously analysed by VirusTotal")
    st = r.json()["data"]["attributes"]["last_analysis_stats"]
    bad, total = st.get("malicious", 0) + st.get("suspicious", 0), max(sum(st.values()), 1)
    return _result("VirusTotal", "ok", bad >= 2, min(100, int(bad / total * 400)), f"{bad} of {total} engines flagged this URL")


async def safe_browsing(client: httpx.AsyncClient, url: str, host: str):
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return _result("Google Safe Browsing", "skipped", detail="Set GOOGLE_SAFE_BROWSING_KEY to enable")
    body = {"client": {"clientId": "cybershield-ai", "clientVersion": "1.0"}, "threatInfo": {
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    r = await client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body)
    m = r.json().get("matches")
    if m:
        return _result("Google Safe Browsing", "ok", True, 95, f"Flagged as {m[0]['threatType'].replace('_', ' ').lower()}")
    return _result("Google Safe Browsing", "ok", False, 0, "No match")


async def lookup_all(url: str, host: str) -> dict:
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
        async def guarded(fn, name):
            try:
                return await fn(client, url, host) if fn is not local_blocklist else await fn(url, host)
            except Exception as e:  # network errors must never break a scan
                return _result(name, "error", detail=f"Lookup failed: {type(e).__name__}")
        res = await asyncio.gather(guarded(local_blocklist, "Local blocklist"), guarded(urlhaus, "URLhaus"),
                                   guarded(virustotal, "VirusTotal"), guarded(safe_browsing, "Google Safe Browsing"))
    active = [r for r in res if r["status"] == "ok"]
    confirmed = [r for r in active if r["malicious"]]
    external = [r for r in active if r["source"] != "Local blocklist"]
    return {"sources": res, "active": len(active), "external_active": len(external), "confirmed": len(confirmed),
            "score": max([r["score"] for r in active], default=0), "consensus": len(confirmed) / len(active) if active else None}
