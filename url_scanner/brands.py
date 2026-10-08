"""Brand catalogue used for impersonation / typosquatting detection."""

BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "gmail.com", "youtube.com", "goo.gl", "google.co.in"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "office365.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "amzn.to"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com", "githubusercontent.com"],
    "adobe": ["adobe.com"],
    "spotify": ["spotify.com"],
    "ebay": ["ebay.com"],
    "walmart": ["walmart.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citibank.com", "citi.com"],
    "hdfc": ["hdfcbank.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "icici": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "flipkart": ["flipkart.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "indiapost": ["indiapost.gov.in"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "yahoo": ["yahoo.com"],
    "zoom": ["zoom.us"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "docusign": ["docusign.com", "docusign.net"],
}

# Other well-known, trustworthy domains (not brands we monitor for impersonation).
TRUSTED_DOMAINS = {
    "wikipedia.org", "mozilla.org", "python.org", "stackoverflow.com", "reddit.com", "bbc.com",
    "bbc.co.uk", "nytimes.com", "cloudflare.com", "medium.com", "kaggle.com", "nasa.gov",
    "irctc.co.in", "gov.in", "nic.in", "who.int", "openai.com", "anthropic.com", "npmjs.com",
    "pypi.org", "w3.org", "ibm.com", "oracle.com", "salesforce.com", "slack.com", "notion.so",
    "canva.com", "udemy.com", "coursera.org", "soa.ac.in", "wordpress.com", "mongodb.com",
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"}

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "zip", "mov", "country",
                   "kim", "men", "loan", "support", "icu", "cyou", "buzz", "monster", "rest", "cam", "su"}

SUSPICIOUS_KEYWORDS = ["login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "confirm",
                       "banking", "password", "wallet", "support", "billing", "invoice", "unlock", "suspend", "recover",
                       "authenticate", "webscr", "validate", "security", "alert", "claim", "prize", "refund", "otp", "kyc"]

MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "org.in", "ac.in", "gov.in", "net.in", "co.jp",
                  "com.br", "co.za", "com.cn", "co.nz", "com.sg", "com.mx", "edu.in", "res.in", "nic.in"}
