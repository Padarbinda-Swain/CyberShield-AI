"""Explainable social-engineering indicators. Each rule = (id, label, regex, weight, explanation)."""
import re

RULES = [
    ("urgency", "Urgency", r"\b(immediately|urgent(ly)?|right now|within \d+ ?(hours?|hrs|minutes?)|today|asap|last warning|final notice|act fast|hurry|expires?( today)?|before midnight)\b", 14,
     "Creates artificial time pressure so you act before thinking."),
    ("threat", "Threat / fear", r"\b(blocked|suspended|deactivated|terminated|legal action|arrest|warrant|penalty|locked|limited|will be closed|unauthori[sz]ed|fraud(ulent)?|compromised)\b", 16,
     "Uses fear of losing access or legal trouble to pressure you."),
    ("credentials", "Asks for credentials / OTP", r"\b(otp|one[- ]time (password|code)|password|passcode|upi pin|\bpin\b|cvv|card number|verification code|6 digit code|security code|login details|credentials)\b", 22,
     "Requests secrets that legitimate organisations never ask for by message."),
    ("sensitive_id", "Asks for identity / bank details", r"\b(aadhaar|aadhar|pan (card|number)|ssn|social security|bank (details|account)|account number|kyc|passport)\b", 18,
     "Asks for personal identity or banking information."),
    ("reward", "Reward / lottery bait", r"\b(congratulations|you (have )?won|lucky (winner|draw)|winner|prize|lottery|free gift|giveaway|selected for|claim (your|now))\b", 20,
     "Promises an unexpected reward - a classic bait."),
    ("financial", "Money request", r"\b(processing fee|registration fee|redelivery fee|customs charges?|pay (now|a|the)|send \d|transfer|wire|gift card|refund|bitcoin|btc|crypto)\b", 14,
     "Asks you to pay or send money."),
    ("authority", "Fake authority", r"\b(income tax|irs|police|customs|government|bank manager|customer care|security team|it department|microsoft support|amazon support|ministry|reserve bank|rbi|cbi|court)\b", 10,
     "Claims to be an authority to appear trustworthy."),
    ("verify", "Fake verification", r"\b(verify (your )?(account|identity|details)|confirm (your )?(identity|details|account)|re-?validate|update (your )?(kyc|details|account|address|card)|reactivate|restore access)\b", 18,
     "Pushes you to 'verify' or 'update' details on a link."),
    ("job_invest", "Job / investment bait", r"\b(work from home|earn \S+ (per|a|every) (day|week)|guaranteed returns?|double your money|zero risk|no experience needed|part[- ]time job|\d{3}% profit|trading signals?|vip group)\b", 18,
     "Offers unrealistic earnings - typical of job and investment scams."),
    ("cta_link", "Suspicious call to action", r"\b(click|tap|open|visit|log ?in|sign ?in|download|install)\b.{0,40}(link|here|below|http|www\.)", 12,
     "Pushes you to click a link or install something."),
    ("secrecy", "Secrecy request", r"\b(do not (tell|share|ignore)|keep (this )?(confidential|secret)|don'?t tell)\b", 8,
     "Tells you not to consult anyone - isolation is a manipulation tactic."),
]
COMPILED = [(i, l, re.compile(p, re.I | re.S), w, e) for i, l, p, w, e in RULES]
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+|\b[a-z0-9-]+\.(?:xyz|top|tk|ml|ga|cf|gq|click|link|info|ly)\b/?[^\s]*", re.I)
CAPS_RE = re.compile(r"\b[A-Z]{4,}\b")


def run_rules(text: str):
    hits = []
    for rid, label, rx, weight, expl in COMPILED:
        m = rx.search(text)
        if m:
            hits.append({"id": rid, "label": label, "weight": weight, "explanation": expl, "match": m.group(0)[:60]})
    return hits


def extract_links(text: str):
    return list(dict.fromkeys(m.group(0).rstrip(".,;") for m in URL_RE.finditer(text)))[:15]
