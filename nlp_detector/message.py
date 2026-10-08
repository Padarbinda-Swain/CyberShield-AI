"""Message / SMS / email analysis pipeline."""
from __future__ import annotations
import asyncio
from risk_engine.engine import config, fuse, recommendations
from url_scanner.analyzer import analyze_url
from .analyzer import CATEGORY_NAMES, analyze_text
from .email_parser import email_meta_findings, parse_email

SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}


async def _scan_links(urls, use_live):
    urls = urls[:3]
    res = await asyncio.gather(*[analyze_url(u, use_live=use_live) for u in urls], return_exceptions=True)
    return [{"url": u, "risk_score": r["risk_score"], "verdict": r["verdict"], "label": r["label"], "top_reason": r["reasons"][0]["text"] if r["reasons"] else ""}
            for u, r in zip(urls, res) if isinstance(r, dict)]


async def analyze_message(text: str, kind: str = "message", use_live: bool = True) -> dict:
    email = None
    body = text
    if kind == "email":
        email = parse_email(text)
        body = ((email["subject"] + ". ") if email["subject"] else "") + email["body"]
    nlp = analyze_text(body)
    links = list(nlp["links"]) + [l["href"] for l in (email or {}).get("html_links", []) if l["href"].startswith("http")]
    links = list(dict.fromkeys(links))
    scanned = await _scan_links(links, use_live) if links else []
    meta_score, meta_reasons = (email_meta_findings(email) if email and email["is_raw_email"] else (0, []))

    reasons = []
    for h in sorted(nlp["rule_hits"], key=lambda h: -h["weight"]):
        reasons.append({"text": f"{h['label']}: {h['explanation']} (\"{h['match']}\")", "severity": "high" if h["weight"] >= 18 else "medium", "source": "nlp"})
    if nlp["category"] not in ("legitimate",) and nlp["ml_available"]:
        reasons.insert(0, {"text": f"NLP model flags this as: {nlp['category_name']} ({nlp['ml_confidence']:.0f}% model confidence).", "severity": "high", "source": "ml"})
    for l in scanned:
        if l["verdict"] != "SAFE":
            reasons.append({"text": f"Link {l['url'][:60]} is {l['verdict'].replace('_', ' ').lower()} (score {l['risk_score']}): {l['top_reason']}", "severity": "high" if l["verdict"] == "HIGH_RISK" else "medium", "source": "links"})
    reasons += meta_reasons

    signals = [{"name": "NLP model", "key": "nlp_ml", "score": nlp["ml_score"], "confidence": 0.6 + nlp["ml_confidence"] / 250}] if nlp["ml_available"] else []
    signals.append({"name": "Social-engineering rules", "key": "nlp_rules", "score": nlp["rule_score"]})
    if scanned: signals.append({"name": "Embedded links", "key": "links", "score": max(l["risk_score"] for l in scanned)})
    if email and email["is_raw_email"]: signals.append({"name": "Sender & attachments", "key": "email_meta", "score": meta_score})
    ov = config()["overrides"]
    floors = []
    if scanned and max(l["risk_score"] for l in scanned) >= config()["thresholds"]["suspicious_max"] + 1:
        floors.append((ov["link_high_risk_floor"], "A link in the message is high risk"))
    cred = [h for h in nlp["rule_hits"] if h["id"] in ("credentials",)]
    if cred and any(h["id"] in ("urgency", "threat", "verify", "reward") for h in nlp["rule_hits"]):
        floors.append((ov["credential_request_floor"], "Asks for credentials under pressure"))
    result = fuse(signals, floors)
    verdict = result["verdict"]
    cat = nlp["category"] if nlp["category"] != "legitimate" else ("phishing_email" if kind == "email" else "suspicious_message")
    if verdict == "SAFE": cat = "legitimate"
    threat = CATEGORY_NAMES.get(cat) or {"phishing_email": "Phishing email", "suspicious_message": "Possible social engineering"}.get(cat, cat)
    if kind == "email" and verdict != "SAFE" and cat == "suspicious_message": threat = "Phishing email"
    if verdict == "SAFE" and not reasons:
        reasons.append({"text": "No social-engineering patterns, risky links or sender anomalies detected.", "severity": "info", "source": "nlp"})
    reasons.sort(key=lambda r: SEV[r["severity"]])
    highlight = [h["match"] for h in nlp["rule_hits"]] + [t["term"] for t in nlp["top_terms"]]
    return {
        "input_type": kind, "input": text[:4000], "verdict": verdict, "label": cat, "threat_type": threat,
        "risk_score": result["risk_score"], "confidence": result["confidence"], "reasons": reasons[:12],
        "recommendations": recommendations(verdict, cat, kind), "signals": result["signals"], "adjustments": result["adjustments"],
        "details": {"highlights": highlight[:20], "indicators": nlp["rule_hits"], "top_terms": nlp["top_terms"], "probabilities": nlp["probabilities"],
                    "links": scanned, "email": ({k: v for k, v in email.items() if k != "body"} if email and email["is_raw_email"] else None)},
    }
