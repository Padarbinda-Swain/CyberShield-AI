"""Safe email parsing: headers, body text, links and attachment METADATA only. Attachments are never opened or executed."""
from __future__ import annotations
import re
from email import policy
from email.parser import BytesParser
from html import unescape
from url_scanner.features import detect_brand, is_trusted, registered_domain

RISKY_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "wsf", "jar", "msi", "ps1", "lnk", "iso", "img", "hta", "apk"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlsb"}
HREF = re.compile(r"""<a\s[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""", re.I | re.S)


def _strip_html(h: str) -> str:
    h = re.sub(r"(?is)<(script|style).*?</\1>", " ", h)
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", h))).strip()


def parse_email(raw: bytes | str) -> dict:
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8", "ignore")
    looks_like_eml = bool(re.match(rb"(?i)\s*(received|from|return-path|delivered-to|mime-version|subject|date|to|message-id)\s*:", data[:300]))
    if not looks_like_eml:
        return {"is_raw_email": False, "subject": "", "from": "", "from_domain": "", "reply_to": "", "body": data.decode("utf-8", "ignore"), "html_links": [], "attachments": [], "auth": {}}
    msg = BytesParser(policy=policy.default).parsebytes(data)
    body_part = msg.get_body(preferencelist=("plain", "html"))
    body, html = "", ""
    try:
        if body_part: body = body_part.get_content()
        h = msg.get_body(preferencelist=("html",))
        html = h.get_content() if h else ""
    except Exception:
        pass
    if body_part is not None and body_part.get_content_type() == "text/html":
        body = _strip_html(body)
    links = [{"href": m.group(1), "text": _strip_html(m.group(2))[:80]} for m in HREF.finditer(html or "")][:40]
    atts = []
    for part in msg.iter_attachments():
        fn = part.get_filename() or "unnamed"
        atts.append({"name": fn[:120], "type": part.get_content_type(), "size": len(part.get_payload(decode=True) or b"")})
    auth_blob = " ".join(str(msg.get(h, "")) for h in ("Authentication-Results", "Received-SPF", "ARC-Authentication-Results")).lower()
    auth = {k: ("fail" if re.search(rf"{k}=(fail|softfail|none|neutral)", auth_blob) else "pass" if f"{k}=pass" in auth_blob else "unknown") for k in ("spf", "dkim", "dmarc")}
    frm = msg.get("From")
    addr = frm.addresses[0] if frm and getattr(frm, "addresses", None) else None
    rt = msg.get("Reply-To")
    rt_addr = rt.addresses[0].addr_spec if rt and getattr(rt, "addresses", None) else ""
    return {"is_raw_email": True, "subject": str(msg.get("Subject", ""))[:200], "from": str(frm or "")[:200],
            "display_name": addr.display_name if addr else "", "from_domain": (addr.domain if addr else "").lower(),
            "reply_to": rt_addr, "body": (body or "").strip(), "html_links": links, "attachments": atts, "auth": auth}


def email_meta_findings(e: dict) -> tuple[int, list[dict]]:
    """Return (score 0-100, reasons) from sender / header / attachment / link-text analysis."""
    score, reasons = 0, []
    def add(pts, text, sev):
        nonlocal score; score += pts; reasons.append({"text": text, "severity": sev, "source": "email"})
    d = e.get("from_domain", "")
    if d:
        b = detect_brand(d)
        if b: add(40, f"Sender domain '{d}' imitates {b['brand'].title()}.", "high")
        dn = (e.get("display_name") or "").lower()
        if dn and not is_trusted(d):
            for brand in ("paypal", "microsoft", "amazon", "google", "apple", "netflix", "bank", "hdfc", "sbi", "icici"):
                if brand in dn and brand not in d:
                    add(30, f"Display name claims to be '{e['display_name']}' but the sender domain is {d}.", "high"); break
    if e.get("reply_to") and e.get("from_domain") and registered_domain(e["reply_to"].split("@")[-1]) != registered_domain(e["from_domain"]):
        add(20, "Reply-To address is on a different domain than the sender.", "medium")
    for k, v in (e.get("auth") or {}).items():
        if v == "fail": add(15, f"{k.upper()} authentication did not pass – the sender may be spoofed.", "high")
    for a in e.get("attachments", []):
        ext = a["name"].lower().rsplit(".", 1)[-1] if "." in a["name"] else ""
        if ext in RISKY_EXT or re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|bat|vbs|lnk)$", a["name"].lower()):
            add(35, f"Attachment '{a['name']}' is an executable/script type – never open it.", "high")
        elif ext in MACRO_EXT:
            add(20, f"Attachment '{a['name']}' can contain macros.", "medium")
        elif ext in ("html", "htm", "zip", "rar", "7z"):
            add(12, f"Attachment '{a['name']}' ({ext}) is commonly used to hide phishing pages or malware.", "medium")
    for l in e.get("html_links", []):
        t = l["text"].lower()
        m = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", t)
        try:
            from urllib.parse import urlparse
            hh = urlparse(l["href"]).hostname or ""
        except Exception:
            hh = ""
        if m and hh and registered_domain(m.group(1)) != registered_domain(hh):
            add(30, f"A link shows '{m.group(1)}' but actually goes to {hh}.", "high"); break
    return min(100, score), reasons
