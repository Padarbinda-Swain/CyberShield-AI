"""Static (no-network) URL feature extraction + brand impersonation detection."""
from __future__ import annotations
import ipaddress, math, re
from collections import Counter
from urllib.parse import urlparse
from .brands import (BRANDS, MULTI_SUFFIXES, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, TRUSTED_DOMAINS, URL_SHORTENERS)

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "num_dots", "num_subdomains", "num_hyphens", "num_digits",
    "digit_ratio", "num_special", "has_at", "has_ip", "is_https", "keyword_count", "suspicious_tld",
    "entropy", "num_params", "brand_hit", "brand_typo", "is_punycode", "is_shortener", "nonstd_port",
    "double_slash_path", "executable_ext", "long_label",
]


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    return raw


def split_host(host: str):
    """Return (subdomain, registered_name, suffix). Dependency-free public-suffix approximation."""
    host = host.lower().strip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "", host, ""
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) < 2:
        return "", host, ""
    suffix_len = 2 if ".".join(parts[-2:]) in MULTI_SUFFIXES else 1
    if len(parts) <= suffix_len:
        return "", host, ""
    name = parts[-suffix_len - 1]
    return ".".join(parts[: -suffix_len - 1]), name, ".".join(parts[-suffix_len:])


def registered_domain(host: str) -> str:
    sub, name, suffix = split_host(host)
    return f"{name}.{suffix}" if suffix else name


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in c.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def deleet(s: str) -> str:
    return s.lower().translate(LEET).replace("rn", "m").replace("vv", "w")


def is_trusted(host: str) -> bool:
    reg = registered_domain(host)
    if reg in TRUSTED_DOMAINS:
        return True
    return any(reg in doms for doms in BRANDS.values())


def detect_brand(host: str) -> dict | None:
    """Detect likely brand impersonation. Returns None for legitimate / unrelated domains."""
    host = host.lower()
    if is_trusted(host):
        return None
    sub, name, suffix = split_host(host)
    tokens = [t for t in re.split(r"[^a-z0-9]+", f"{sub}.{name}".lower()) if t]
    full = f"{sub}.{name}"
    for brand in BRANDS:
        # 1) exact brand word anywhere in the host (e.g. paypal-login.com, paypal.secure-check.net)
        if brand in tokens:
            return {"brand": brand, "kind": "brand_keyword", "evidence": f"'{brand}' appears in a domain that does not belong to it"}
        # 2) look-alike characters: g00gle, paypa1, amaz0n, rnicrosoft
        for t in tokens + [deleet(name)]:
            d = deleet(t)
            if (len(brand) >= 5 and brand in d and brand not in t) or d == brand and t != brand:
                return {"brand": brand, "kind": "lookalike_chars",
                        "evidence": f"character substitution makes '{t}' look like '{brand}'"}
        if len(brand) >= 5 and brand in deleet(full):
            return {"brand": brand, "kind": "brand_keyword", "evidence": f"'{brand}' embedded inside the domain name"}
        # 3) typosquatting by edit distance
        for t in tokens:
            if len(brand) >= 5 and abs(len(t) - len(brand)) <= 2 and 0 < levenshtein(deleet(t), brand) <= (1 if len(brand) < 8 else 2):
                return {"brand": brand, "kind": "typosquat", "evidence": f"'{t}' is one or two characters away from '{brand}'"}
    return None


def parse(url: str):
    url = normalize_url(url)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    return url, p, host


def extract_features(url: str) -> dict:
    url, p, host = parse(url)
    sub, name, suffix = split_host(host)
    try:
        ipaddress.ip_address(host.strip("[]")); has_ip = 1
    except ValueError:
        has_ip = 0
    low = url.lower()
    kw = sum(low.count(k) for k in SUSPICIOUS_KEYWORDS)
    brand = detect_brand(host) if not has_ip else None
    labels = host.split(".")
    return {
        "url_length": len(url), "host_length": len(host), "path_length": len(p.path or ""),
        "num_dots": host.count("."), "num_subdomains": len([s for s in sub.split(".") if s]),
        "num_hyphens": host.count("-"), "num_digits": sum(c.isdigit() for c in host),
        "digit_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "num_special": len(re.findall(r"[^a-zA-Z0-9./:\-]", url)), "has_at": int("@" in (p.netloc or "")),
        "has_ip": has_ip, "is_https": int(p.scheme == "https"), "keyword_count": min(kw, 8),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS), "entropy": shannon_entropy(name),
        "num_params": len([q for q in (p.query or "").split("&") if q]),
        "brand_hit": int(bool(brand and brand["kind"] in ("brand_keyword", "lookalike_chars"))),
        "brand_typo": int(bool(brand and brand["kind"] == "typosquat")),
        "is_punycode": int("xn--" in host), "is_shortener": int(registered_domain(host) in URL_SHORTENERS),
        "nonstd_port": int(p.port not in (None, 80, 443)), "double_slash_path": int("//" in (p.path or "")),
        "executable_ext": int(bool(re.search(r"\.(exe|apk|scr|bat|msi|jar|zip|rar|js|vbs)(\?|$)", (p.path or "").lower()))),
        "long_label": int(any(len(l) > 25 for l in labels)),
    }
