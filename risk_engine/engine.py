"""Risk engine: fuses ML, rules, domain, NLP and threat-intel signals into one explainable score.
All thresholds/weights live in config.json (override path with RISK_CONFIG env)."""
from __future__ import annotations
import json, os, pathlib

CFG_PATH = pathlib.Path(os.getenv("RISK_CONFIG", pathlib.Path(__file__).parent / "config.json"))
_cfg = None
PEAK = float(os.getenv("RISK_PEAK_BLEND", "0.4"))


def config() -> dict:
    global _cfg
    if _cfg is None:
        _cfg = json.loads(CFG_PATH.read_text())
    return _cfg


def classify(score: float) -> str:
    t = config()["thresholds"]
    return "SAFE" if score <= t["safe_max"] else "SUSPICIOUS" if score <= t["suspicious_max"] else "HIGH_RISK"


def fuse(signals: list[dict], floors: list[tuple[int, str]] = (), cap: tuple[int, str] | None = None) -> dict:
    """signals: [{name, key, score 0-100, confidence 0-1}]. Missing signals are simply left out and
    the remaining weights are re-normalised, so no single source (or API) can dominate."""
    w = config()["weights"]
    used = [s for s in signals if s.get("score") is not None]
    tot = sum(w.get(s["key"], 0.2) * s.get("confidence", 1) for s in used) or 1
    score = sum(s["score"] * w.get(s["key"], 0.2) * s.get("confidence", 1) for s in used) / tot
    # blend the weighted mean with the strongest signal so one clear red flag is not diluted by quiet signals
    peak = max((s["score"] for s in used), default=0)
    score = (1 - PEAK) * score + PEAK * peak
    notes = []
    for fl, why in floors:
        if score < fl:
            score = fl; notes.append(why)
    if cap and score > cap[0]:
        score = cap[0]; notes.append(cap[1])
    score = max(0, min(100, round(score)))
    agree = 1.0
    if len(used) > 1:
        vals = [s["score"] for s in used]; agree = 1 - (max(vals) - min(vals)) / 200
    # confidence: distance from the decision boundaries + signal agreement + number of independent signals
    t = config()["thresholds"]
    margin = min(abs(score - t["safe_max"]), abs(score - t["suspicious_max"]), 25) / 25
    conf = round(100 * (0.45 + 0.25 * margin + 0.2 * agree + 0.1 * min(len(used), 4) / 4))
    return {"risk_score": score, "verdict": classify(score), "confidence": min(conf, 99), "adjustments": notes,
            "signals": [{"name": s["name"], "score": round(s["score"]), "weight": round(w.get(s["key"], 0.2), 2)} for s in used]}


def recommendations(verdict: str, threat: str, kind: str) -> list[str]:
    if verdict == "HIGH_RISK":
        rec = ["Do not open the link, reply, or enter any password, OTP, card or bank details.",
               "Do not download or run any attachment or file from this source.",
               "If you already interacted with it, change your passwords and contact your bank immediately."]
        if kind in ("message", "email"):
            rec.append("Report it (e.g. your email provider's 'Report phishing', or cybercrime.gov.in in India) and delete it.")
        else:
            rec.append("Close the page and report the URL to your IT / security team or Google Safe Browsing.")
        return rec
    if verdict == "SUSPICIOUS":
        return ["Treat this with caution - verify the sender or site through an official channel you already trust.",
                "Type the organisation's address into your browser yourself instead of clicking the link.",
                "Never share OTPs, PINs or passwords, even if the request seems routine."]
    return ["No strong threat signals found. Stay alert - no scan can guarantee safety.",
            "Keep your browser and OS updated and use multi-factor authentication."]
