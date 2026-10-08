"""Social-engineering analysis: ML probabilities (TF-IDF + best model) + transparent rule indicators."""
from __future__ import annotations
import pathlib
import joblib, numpy as np
from .rules import CAPS_RE, extract_links, run_rules

ART = pathlib.Path(__file__).resolve().parent.parent / "ml" / "artifacts"
_model = _explainer = None
CATEGORY_NAMES = {
    "banking_scam": "Banking scam", "delivery_scam": "Delivery scam", "lottery_scam": "Lottery / reward scam",
    "job_scam": "Job scam", "investment_scam": "Investment scam", "government_scam": "Fake government message",
    "otp_scam": "OTP / payment scam", "account_verification": "Account-verification phishing", "legitimate": "No threat detected",
}


def _load():
    global _model, _explainer
    if _model is None:
        _model = joblib.load(ART / "text_model.joblib")
        _explainer = joblib.load(ART / "text_explainer.joblib")
    return _model, _explainer


def model_ready() -> bool:
    return (ART / "text_model.joblib").exists()


def top_terms(text: str, category: str, k: int = 5):
    """Per-word contribution (tfidf * coefficient) from the linear explainer model."""
    _, ex = _load()
    pipe = ex["model"]; vec, clf = pipe.steps[0][1], pipe.steps[-1][1]
    x = vec.transform([text]); names = vec.get_feature_names_out()
    ci = list(clf.classes_).index(category)
    contrib = x.multiply(clf.coef_[ci]).tocoo()
    pairs = sorted(zip(contrib.col, contrib.data), key=lambda t: -t[1])
    return [{"term": names[c], "weight": round(float(v), 3)} for c, v in pairs[:k] if v > 0]


def analyze_text(text: str) -> dict:
    text = (text or "").strip()
    hits = run_rules(text)
    links = extract_links(text)
    rule_score = min(100, sum(h["weight"] for h in hits) + (8 if CAPS_RE.search(text) and len(CAPS_RE.findall(text)) >= 3 else 0) + (8 if links else 0))
    out = {"rule_hits": hits, "links": links, "rule_score": rule_score, "ml_available": model_ready(),
           "category": "legitimate", "category_name": CATEGORY_NAMES["legitimate"], "ml_score": 0, "ml_confidence": 0, "top_terms": [], "probabilities": {}}
    if out["ml_available"]:
        m, _ = _load()
        proba = m["model"].predict_proba([text])[0]
        classes = list(m["model"].classes_)
        probs = dict(zip(classes, map(float, proba)))
        threat = {c: p for c, p in probs.items() if c != "legitimate"}
        cat = max(threat, key=threat.get)
        p_threat = 1.0 - probs.get("legitimate", 0.0)
        out.update(ml_score=round(p_threat * 100, 1), ml_confidence=round(max(proba) * 100, 1), probabilities={k: round(v, 3) for k, v in probs.items()})
        if p_threat >= 0.5:
            out.update(category=cat, category_name=CATEGORY_NAMES.get(cat, cat), top_terms=top_terms(text, cat))
    elif hits:
        out.update(category="suspicious_message", category_name="Possible social engineering")
    return out
