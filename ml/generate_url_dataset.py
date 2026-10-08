"""Builds a labelled URL dataset (safe / suspicious / phishing / malicious).

The bundled generator is SYNTHETIC so the project runs offline. For a real deployment replace
`ml/data/urls.csv` (columns: url,label) with Tranco/Alexa (safe) + PhishTank/OpenPhish (phishing)
+ URLhaus (malicious) and re-run `python -m ml.train_url_model`.
"""
import random, string, csv, pathlib
from url_scanner.brands import BRANDS, SUSPICIOUS_TLDS

R = random.Random(42)
OUT = pathlib.Path(__file__).parent / "data" / "urls.csv"
SAFE_HOSTS = [d for doms in BRANDS.values() for d in doms] + [
    "wikipedia.org", "mozilla.org", "python.org", "stackoverflow.com", "reddit.com", "bbc.com", "nytimes.com",
    "medium.com", "kaggle.com", "nasa.gov", "coursera.org", "udemy.com", "notion.so", "canva.com", "soa.ac.in",
    "irctc.co.in", "cloudflare.com", "wordpress.com", "slack.com", "mongodb.com", "npmjs.com", "w3.org",
    "ycombinator.com", "arxiv.org", "khanacademy.org", "weather.com", "imdb.com", "quora.com", "zomato.com",
]
SAFE_PATHS = ["", "/", "/about", "/products", "/search?q=python", "/docs/getting-started", "/blog/2024/ai-trends",
              "/help/contact", "/watch?v=dQw4w9WgXcQ", "/in/some-person", "/courses/data-science", "/r/learnprogramming", "/news/world",
              "/account/settings", "/login", "/signin", "/pricing", "/support", "/store/apps/details?id=com.app"]
KW = ["login", "verify", "secure", "account", "update", "confirm", "banking", "support", "billing", "signin", "wallet", "unlock", "recover", "validate", "kyc"]
TLDS_BAD = sorted(SUSPICIOUS_TLDS)
TLDS_OK = ["com", "net", "org", "in", "co", "info", "online", "site"]
LEET = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}


def rnd(n, alpha=string.ascii_lowercase + string.digits):
    return "".join(R.choice(alpha) for _ in range(n))


def leet(word):
    idx = [i for i, c in enumerate(word) if c in LEET]
    if not idx:
        return word[:-1] + R.choice("xq") + word[-1]
    i = R.choice(idx)
    return word[:i] + LEET[word[i]] + word[i + 1:]


def typo(word):
    i = R.randrange(1, len(word) - 1)
    return R.choice([word[:i] + word[i + 1:], word[:i] + word[i] + word[i:], word[:i] + word[i + 1] + word[i] + word[i + 2:]]) if len(word) > 4 else word + "x"


def safe():
    h = R.choice(SAFE_HOSTS)
    if R.random() < 0.35:
        h = R.choice(["www.", "mail.", "docs.", "blog.", "support.", "accounts.", "m."]) + h
    return f"{R.choice(['https', 'https', 'https', 'http'])}://{h}{R.choice(SAFE_PATHS)}"


def suspicious():
    k = R.random()
    tld = R.choice(TLDS_OK + TLDS_BAD)
    if k < 0.3:
        return f"http://{rnd(R.randint(6, 12), string.ascii_lowercase)}.{tld}/{R.choice(KW)}"
    if k < 0.55:
        return f"https://{R.choice(['free', 'best', 'cheap', 'daily', 'my'])}-{R.choice(['deals', 'offers', 'coupons', 'rewards', 'jobs'])}-{rnd(4)}.{tld}/?ref={rnd(6)}"
    if k < 0.8:
        return f"http://{R.choice(['bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy'])}/{rnd(7, string.ascii_letters + string.digits)}"
    return f"http://{rnd(5)}.{rnd(6, string.ascii_lowercase)}.{tld}:{R.choice([8080, 8443, 81])}/{R.choice(KW)}.html"


def phishing():
    b = R.choice(list(BRANDS))
    k = R.random()
    kw1, kw2 = R.choice(KW), R.choice(KW)
    tld = R.choice(TLDS_OK + TLDS_BAD)
    if k < 0.25:
        return f"http://{leet(b)}-{kw1}.{tld}/{kw2}"
    if k < 0.45:
        return f"https://{b}-{kw1}-{kw2}.{tld}/{R.choice(['index.php', 'webscr', 'auth', ''])}"
    if k < 0.65:
        return f"https://{b}.{kw1}.{rnd(R.randint(5, 9), string.ascii_lowercase)}.{tld}/{kw2}?id={rnd(10)}"
    if k < 0.8:
        return f"http://{typo(b)}.{R.choice(['com', 'net', tld])}/{kw1}"
    if k < 0.9:
        return f"http://{'.'.join(str(R.randint(1, 254)) for _ in range(4))}/{b}/{kw1}.php"
    return f"https://{b}.com@{rnd(8, string.ascii_lowercase)}.{tld}/{kw1}"


def malicious():
    k = R.random()
    tld = R.choice(TLDS_BAD + ["com", "ru", "cn"])
    if k < 0.4:
        return f"http://{rnd(R.randint(8, 14))}.{tld}/{R.choice(['download', 'files', 'update', 'dl'])}/{rnd(6)}.{R.choice(['exe', 'apk', 'scr', 'zip', 'js'])}"
    if k < 0.7:
        return f"http://{'.'.join(str(R.randint(1, 254)) for _ in range(4))}:{R.choice([80, 8080, 8000])}/{rnd(4)}/{rnd(8)}.{R.choice(['exe', 'sh', 'php', 'bat'])}"
    return f"http://{rnd(R.randint(10, 18))}.{tld}/wp-content/{rnd(5)}/{rnd(7)}.php?id={rnd(12)}&k={rnd(6)}"


def main(n_per_class=2500):
    rows = []
    for label, gen in [("safe", safe), ("suspicious", suspicious), ("phishing", phishing), ("malicious", malicious)]:
        rows += [(gen(), label) for _ in range(n_per_class)]
    # Label noise (3%) keeps metrics honest and prevents trivially perfect scores.
    labels = ["safe", "suspicious", "phishing", "malicious"]
    rows = [(u, R.choice(labels) if R.random() < 0.03 else l) for u, l in rows]
    R.shuffle(rows)
    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["url", "label"]); w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {OUT}")


if __name__ == "__main__":
    main()
