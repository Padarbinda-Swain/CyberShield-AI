"""End-to-end URL / website analysis: ML + rules + live domain signals + threat intelligence -> risk."""
from __future__ import annotations
import pathlib
import joblib, numpy as np, pandas as pd
from risk_engine.engine import config, fuse, recommendations
from threat_intelligence.providers import lookup_all
from .features import FEATURE_NAMES, detect_brand, extract_features, is_trusted, normalize_url, parse, split_host, registered_domain
from .brands import SUSPICIOUS_KEYWORDS, URL_SHORTENERS
from .live import live_checks

ART = pathlib.Path(__file__).resolve().parent.parent / "ml" / "artifacts"
_bundle = None
THREAT_NAMES = {"safe": "No threat detected", "suspicious": "Suspicious website", "phishing": "Phishing", "malicious": "Malware / malicious site"}


def _model():
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(ART / "url_model.joblib")
    return _bundle


def model_ready() -> bool:
    return (ART / "url_model.joblib").exists()


def ml_predict(feats: dict) -> dict:
    b = _model(); X = pd.DataFrame([feats])[b["features"]]
    proba = b["model"].predict_proba(X)[0]
    probs = dict(zip(b["classes"], map(float, proba)))
    risk = sum(probs[c] * config()["class_risk"][c] for c in probs)
    est = b["model"].steps[-1][1] if hasattr(b["model"], "steps") else b["model"]
    return {"probs": probs, "label": max(probs, key=probs.get), "score": risk, "confidence": float(max(proba))}


def anatomy(url: str, brand: dict | None, tld_bad: bool):
    _, p, host = parse(url)
    sub, name, suffix = split_host(host)
    parts = [{"text": p.scheme + "://", "kind": "scheme", "flag": p.scheme != "https", "note": "Connection is not encrypted" if p.scheme != "https" else ""}]
    if sub:
        flagged = bool(brand and brand["brand"] in sub.lower())
        parts.append({"text": sub + ".", "kind": "subdomain", "flag": flagged or len(sub.split(".")) >= 3, "note": "Brand name used as a subdomain" if flagged else "Unusually deep subdomain chain" if len(sub.split(".")) >= 3 else ""})
    parts.append({"text": name, "kind": "domain", "flag": bool(brand), "note": f"Looks like {brand['brand']}" if brand else ""})
    if suffix:
        parts.append({"text": "." + suffix, "kind": "tld", "flag": tld_bad, "note": "TLD frequently abused for scams" if tld_bad else ""})
    if p.port: parts.append({"text": f":{p.port}", "kind": "port", "flag": p.port not in (80, 443), "note": "Unusual port"})
    path = (p.path or "") + (("?" + p.query) if p.query else "")
    if path and path != "/":
        kw = [k for k in SUSPICIOUS_KEYWORDS if k in path.lower()]
        parts.append({"text": path[:80] + ("…" if len(path) > 80 else ""), "kind": "path", "flag": bool(kw), "note": f"Contains: {', '.join(kw[:3])}" if kw else ""})
    return parts


def add(reasons, text, sev, source):
    reasons.append({"text": text, "severity": sev, "source": source})


async def analyze_url(raw: str, inspect_site: bool = False, use_live: bool = True) -> dict:
    url, p, host = parse(raw)
    if not host or "." not in host and not host.replace(":", "").isdigit():
        raise ValueError("Please enter a valid URL or domain name, e.g. https://example.com")
    f = extract_features(url)
    sub, name, suffix = split_host(host)
    reg = registered_domain(host)
    trusted = is_trusted(host)
    brand = detect_brand(host) if not f["has_ip"] else None
    reasons, rule = [], 0

    def rule_add(pts, text, sev):
        nonlocal rule
        rule += pts; add(reasons, text, sev, "rules")

    if brand:
        rule_add(45, f"Domain imitates {brand['brand'].title()} – {brand['evidence']}.", "high")
    if f["has_ip"]: rule_add(30, "The address uses a raw IP address instead of a domain name.", "high")
    if f["has_at"]: rule_add(22, "The URL contains '@', which can hide the real destination.", "high")
    if f["is_punycode"]: rule_add(18, "Domain uses punycode (xn--), often used for look-alike characters.", "high")
    if f["suspicious_tld"]: rule_add(15, f"Top-level domain .{suffix.split('.')[-1]} is frequently abused for scams.", "medium")
    if not f["is_https"]: rule_add(10, "The site does not use HTTPS, so data is sent unencrypted.", "medium")
    if f["num_subdomains"] >= 3: rule_add(10, f"Unusually deep subdomain structure ({f['num_subdomains']} levels).", "medium")
    kws = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if len(kws) >= 2 or (kws and not trusted): rule_add(12 if len(kws) < 3 else 16, f"Sensitive keywords in the URL: {', '.join(kws[:4])}.", "medium")
    if f["is_shortener"]: rule_add(12, "A link shortener hides the final destination.", "medium")
    if f["executable_ext"]: rule_add(28, "The URL points directly to a downloadable program or archive.", "high")
    if f["nonstd_port"]: rule_add(8, "Uses a non-standard port.", "low")
    if f["entropy"] > 3.4 and f["host_length"] > 14: rule_add(10, "Domain name looks randomly generated (high entropy).", "medium")
    if f["url_length"] > 90: rule_add(6, f"Very long URL ({f['url_length']} characters).", "low")
    if f["num_hyphens"] >= 3: rule_add(6, "Many hyphens in the domain – common in fake domains.", "low")
    if f["double_slash_path"]: rule_add(5, "Suspicious '//' in the URL path.", "low")
    rule = min(100, rule)

    # --- ML ---
    ml = ml_predict(f) if model_ready() else None
    if ml and ml["label"] != "safe":
        add(reasons, f"ML model classifies the URL as {ml['label']} ({ml['confidence']*100:.0f}% model confidence).", "high" if ml["label"] in ("phishing", "malicious") else "medium", "ml")

    # --- live + threat intel concurrently ---
    import asyncio
    live_task = live_checks(url, host, reg, bool(f["is_https"]), inspect_site) if use_live else asyncio.sleep(0, {"enabled": False})
    live, ti = await asyncio.gather(live_task, lookup_all(url, host))
    domain_score, floors = None, []
    dscore = 0
    if live.get("enabled"):
        dns, dom, tls, page = live.get("dns", {}), live.get("domain", {}), live.get("tls", {}), live.get("page", {})
        if dns.get("blocked"):
            add(reasons, "The host resolves to a private/internal address – not scanned further for safety.", "high", "domain"); dscore += 40
        elif dns.get("resolves") is False:
            add(reasons, "Domain does not resolve in DNS (may be taken down or fake).", "medium", "domain"); dscore += 25
        if dom.get("known"):
            d = dom["age_days"]
            if d < 30: add(reasons, f"Domain was registered only {d} days ago.", "high", "domain"); dscore += 45
            elif d < 180: add(reasons, f"Domain is young ({d} days old).", "medium", "domain"); dscore += 20
        if tls.get("valid") is False:
            add(reasons, f"SSL certificate problem: {tls.get('error')}.", "high", "domain"); dscore += 40
        elif tls.get("valid") and tls.get("age_days", 999) < 14 and not trusted:
            add(reasons, "SSL certificate was issued very recently.", "low", "domain"); dscore += 10
        if page and not page.get("error"):
            if page["redirects"] >= 3: add(reasons, f"Multiple redirects detected ({page['redirects']}).", "medium", "website"); dscore += 20
            if page["redirects"] and registered_domain(page["final_url"].split("/")[2]) != reg:
                add(reasons, "The URL redirects to a different domain.", "medium", "website"); dscore += 15
            if page["has_password_field"] and (brand or not trusted or not f["is_https"]):
                add(reasons, "The page asks for a password.", "medium", "website"); dscore += 15
            if page["external_form_action"]: add(reasons, "A form on the page sends data to a different website.", "high", "website"); dscore += 35
            if page["hidden_iframe"]: add(reasons, "Hidden iframe found on the page.", "high", "website"); dscore += 25
            if page["obfuscated_js"]: add(reasons, "Obfuscated JavaScript patterns found.", "medium", "website"); dscore += 15
            missing = [h for h, ok in page["security_headers"].items() if not ok]
            if len(missing) >= 4: add(reasons, "Most standard security headers are missing.", "low", "website"); dscore += 6
        domain_score = min(100, dscore) if (dom.get("known") or tls or page or dns.get("resolves") is False) else None
    for s in ti["sources"]:
        if s["status"] == "ok" and s["malicious"]:
            add(reasons, f"{s['source']}: {s['detail']}.", "high", "threat_intel")

    # --- fuse ---
    signals = []
    if ml: signals.append({"name": "URL ML model", "key": "ml", "score": ml["score"], "confidence": 0.6 + 0.4 * ml["confidence"]})
    signals.append({"name": "Security rules", "key": "rules", "score": rule})
    if domain_score is not None: signals.append({"name": "Domain & website analysis", "key": "domain", "score": domain_score})
    if ti["external_active"] or ti["confirmed"]: signals.append({"name": "Threat intelligence", "key": "threat_intel", "score": ti["score"], "confidence": 1.0})
    ov = config()["overrides"]
    floors = []
    if ti["confirmed"]: floors.append((ov["ti_confirmed_floor"], "Confirmed by threat intelligence"))
    if f["is_shortener"]: floors.append((35, "Link shortener hides the destination"))
    if brand: floors.append((ov["brand_impersonation_floor"], "Brand impersonation detected"))
    cap = (ov["trusted_domain_cap"], "Well-known trusted domain") if trusted and not ti["confirmed"] else None
    result = fuse(signals, floors, cap)
    verdict = result["verdict"]
    label = ml["label"] if ml else ("phishing" if brand else "suspicious" if rule > 30 else "safe")
    if verdict == "SAFE": label = "safe"
    elif label == "safe": label = "phishing" if brand else "suspicious"
    if brand and verdict != "SAFE" and label == "suspicious": label = "phishing"
    if ti["confirmed"] and label in ("safe", "suspicious"): label = "malicious"
    if verdict == "SAFE" and not reasons:
        add(reasons, "No suspicious structure, reputation or domain signals were found.", "info", "rules")
    if trusted: add(reasons, "Domain belongs to a well-known, trusted organisation.", "info", "rules")
    sev = {"high": 0, "medium": 1, "low": 2, "info": 3}
    reasons.sort(key=lambda r: sev[r["severity"]])
    return {
        "input_type": "website" if inspect_site else "url", "input": url[:2000], "verdict": verdict, "label": label,
        "threat_type": THREAT_NAMES.get(label, label), "risk_score": result["risk_score"], "confidence": result["confidence"],
        "reasons": reasons[:12], "recommendations": recommendations(verdict, label, "url"), "signals": result["signals"],
        "adjustments": result["adjustments"],
        "details": {"anatomy": anatomy(url, brand, bool(f["suspicious_tld"])), "brand": brand, "features": f, "ml": ml and {"probs": {k: round(v, 3) for k, v in ml["probs"].items()}, "model": _model()["name"]},
                    "live": live, "threat_intel": ti, "trusted_domain": trusted},
    }
