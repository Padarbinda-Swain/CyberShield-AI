import asyncio, os, sys, tempfile
os.environ["LIVE_NETWORK_CHECKS"] = "false"
os.environ["LOCAL_DB_PATH"] = tempfile.mkdtemp() + "/db.json"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from url_scanner.features import detect_brand
from url_scanner.analyzer import analyze_url
from nlp_detector.message import analyze_message
from risk_engine.engine import classify


def test_brand_detection():
    assert detect_brand("paypal.com") is None
    for d, b in [("paypa1-login.com", "paypal"), ("g00gle-security.com", "google"), ("amaz0n-support.com", "amazon")]:
        assert detect_brand(d)["brand"] == b


def test_thresholds():
    assert classify(30) == "SAFE" and classify(31) == "SUSPICIOUS" and classify(61) == "HIGH_RISK"


def test_urls():
    bad = asyncio.run(analyze_url("http://paypa1-login.com/verify", use_live=False))
    good = asyncio.run(analyze_url("https://www.wikipedia.org", use_live=False))
    assert bad["verdict"] == "HIGH_RISK" and good["verdict"] == "SAFE"


def test_message():
    r = asyncio.run(analyze_message("Your bank account will be blocked today. Verify immediately using this link http://hdfc-update.top/login", use_live=False))
    assert r["verdict"] == "HIGH_RISK" and r["reasons"]
    ok = asyncio.run(analyze_message("Hey, are we still meeting for lunch tomorrow at 1?", use_live=False))
    assert ok["verdict"] == "SAFE"


def test_api_flow():
    from fastapi.testclient import TestClient
    from backend.app.main import app
    with TestClient(app) as c:
        t = c.post("/api/auth/register", json={"name": "Test User", "email": "t@example.com", "password": "pass12345"}).json()["token"]
        h = {"Authorization": f"Bearer {t}"}
        assert c.post("/api/scan/url", json={"url": "g00gle-security.com"}, headers=h).json()["verdict"] == "HIGH_RISK"
        assert c.get("/api/dashboard", headers=h).json()["total"] == 1
        assert c.get("/api/admin/overview", headers=h).status_code == 403
        assert c.post("/api/scan/url", json={"url": "javascript:alert(1)"}, headers=h).status_code == 422
        assert c.get("/api/scans").status_code == 401
