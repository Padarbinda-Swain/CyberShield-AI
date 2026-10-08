"""Optional live checks (DNS, TLS, RDAP domain age, redirects, page inspection).
SAFETY: the server only ever performs plain network reads. It never renders pages, runs scripts or
downloads/executes files. Every hop is SSRF-guarded (no private, loopback or link-local targets)."""
from __future__ import annotations
import asyncio, ipaddress, os, re, socket, ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
import httpx

LIVE = os.getenv("LIVE_NETWORK_CHECKS", "true").lower() == "true"
UA = {"User-Agent": "CyberShieldAI-Scanner/1.0 (+security analysis; no script execution)"}
MAX_BYTES = 200_000


def _public_ips(host: str):
    infos = socket.getaddrinfo(host, None)
    ips = {i[4][0] for i in infos}
    for ip in ips:
        a = ipaddress.ip_address(ip)
        if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified:
            raise PermissionError(f"blocked non-public address {ip}")
    return sorted(ips)


async def dns_info(host: str) -> dict:
    try:
        ips = await asyncio.to_thread(_public_ips, host)
        return {"resolves": True, "ips": ips[:6]}
    except PermissionError as e:
        return {"resolves": True, "blocked": str(e)}
    except Exception:
        return {"resolves": False, "ips": []}


def _tls(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            c = t.getpeercert()
        exp = datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        start = datetime.strptime(c["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in c.get("issuer", [])).get("organizationName", "unknown")
        return {"valid": True, "issuer": issuer, "expires": exp.date().isoformat(),
                "age_days": (datetime.now(timezone.utc) - start).days, "days_left": (exp - datetime.now(timezone.utc)).days}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": (e.verify_message or "certificate verification failed")}
    except Exception as e:
        return {"valid": None, "error": type(e).__name__}


async def tls_info(host: str) -> dict:
    return await asyncio.to_thread(_tls, host)


async def domain_age(reg_domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=6, follow_redirects=True, headers=UA) as c:
            r = await c.get(f"https://rdap.org/domain/{reg_domain}")
        if r.status_code != 200:
            return {"known": False}
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return {"known": True, "registered": d.date().isoformat(), "age_days": (datetime.now(timezone.utc) - d).days}
    except Exception:
        pass
    return {"known": False}


async def inspect_page(url: str) -> dict:
    """Follow redirects manually (max 5) and statically inspect the final HTML. Nothing is executed."""
    chain, cur, html, headers, status = [], url, "", {}, None
    async with httpx.AsyncClient(timeout=7, follow_redirects=False, headers=UA, verify=True) as c:
        for _ in range(6):
            p = urlparse(cur)
            await asyncio.to_thread(_public_ips, p.hostname)  # SSRF guard on every hop
            async with c.stream("GET", cur) as r:
                status, headers = r.status_code, dict(r.headers)
                chain.append({"url": cur, "status": r.status_code})
                if r.is_redirect and "location" in r.headers:
                    cur = urljoin(cur, r.headers["location"]); continue
                buf = b""
                async for chunk in r.aiter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BYTES: break
                html = buf.decode(r.encoding or "utf-8", errors="ignore")
                break
    final_host = urlparse(chain[-1]["url"]).hostname or ""
    low = html.lower()
    forms = re.findall(r"<form[^>]*action=[\"']?([^\"' >]+)", low)
    ext_form = any(f.startswith("http") and (urlparse(f).hostname or "") != final_host for f in forms)
    sec = {h: (h in {k.lower() for k in headers}) for h in
           ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]}
    return {"final_url": chain[-1]["url"], "redirects": len(chain) - 1, "chain": chain, "status": status,
            "has_password_field": 'type="password"' in low or "type='password'" in low or "type=password" in low,
            "external_form_action": ext_form, "hidden_iframe": bool(re.search(r"<iframe[^>]*(display:\s*none|width=[\"']?0|height=[\"']?0)", low)),
            "meta_refresh": "http-equiv=\"refresh\"" in low, "obfuscated_js": bool(re.search(r"eval\(|unescape\(|atob\(|fromcharcode", low)),
            "title": (re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S) or [None, ""])[1].strip()[:120],
            "security_headers": sec, "server": headers.get("server", "")[:60]}


async def live_checks(url: str, host: str, reg_domain: str, https: bool, inspect: bool) -> dict:
    out = {"enabled": LIVE}
    if not LIVE:
        return out
    dns = await dns_info(host)
    out["dns"] = dns
    if dns.get("blocked") or not dns.get("resolves"):
        return out
    tasks = {"domain": domain_age(reg_domain)}
    if https: tasks["tls"] = tls_info(host)
    if inspect:
        async def safe_inspect():
            try: return await inspect_page(url)
            except Exception as e: return {"error": type(e).__name__}
        tasks["page"] = safe_inspect()
    res = await asyncio.gather(*tasks.values())
    out.update(dict(zip(tasks.keys(), res)))
    return out
