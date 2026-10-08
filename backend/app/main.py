"""CyberShield AI – FastAPI backend."""
from __future__ import annotations
import json, logging, os, pathlib, re, sys, time, uuid
from contextlib import asynccontextmanager

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from database.store import create_store
from nlp_detector.message import analyze_message
from url_scanner.analyzer import analyze_url, model_ready as url_ready
from nlp_detector.analyzer import model_ready as text_ready
from threat_intelligence.providers import BLOCKLIST
from .ratelimit import RateLimitMiddleware
from .security import admin_user, current_user, hash_password, make_token, verify_password

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format='{"t":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s"}')
log = logging.getLogger("cybershield")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$")
STARTED = time.time()
ART = ROOT / "ml" / "artifacts"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not (url_ready() and text_ready()):  # first run: build datasets + train models
        log.warning("Model artifacts missing – training now")
        from ml.train_url_model import main as t1; from ml.train_text_model import main as t2
        t1(); t2()
    app.state.store = await create_store()
    admin = os.getenv("ADMIN_EMAIL", "admin@cybershield.local"); pw = os.getenv("ADMIN_PASSWORD", "ChangeMe!2024")
    if not await app.state.store.get_user_by_email(admin):
        await app.state.store.create_user({"email": admin, "name": "Administrator", "password": hash_password(pw), "role": "admin"})
        log.info("Seeded admin account %s", admin)
    log.info("CyberShield AI ready (db=%s)", app.state.store.kind)
    yield


app = FastAPI(title="CyberShield AI", version="1.0.0", lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")
app.add_middleware(RateLimitMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=[o for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8080").split(",") if o],
                   allow_origin_regex=r"chrome-extension://.*|moz-extension://.*", allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def harden(request: Request, call_next):
    rid = uuid.uuid4().hex[:8]; t = time.time()
    try:
        resp = await call_next(request)
    except Exception:
        log.exception("unhandled error rid=%s path=%s", rid, request.url.path)
        from fastapi.responses import JSONResponse
        resp = JSONResponse({"detail": "Internal error – please try again."}, 500)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                         "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                         "X-Request-ID": rid, "Cache-Control": "no-store"})
    if not request.url.path.startswith("/api/health"):
        log.info("rid=%s %s %s -> %s %dms", rid, request.method, request.url.path, resp.status_code, (time.time() - t) * 1000)
    return resp


# ---------- schemas ----------
class Register(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: str = Field(max_length=254)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def _e(cls, v):
        v = v.strip().lower()
        if not EMAIL_RE.match(v): raise ValueError("Enter a valid email address")
        return v

    @field_validator("password")
    @classmethod
    def _p(cls, v):
        if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)): raise ValueError("Password needs letters and numbers")
        return v

    @field_validator("name")
    @classmethod
    def _n(cls, v): return re.sub(r"[<>]", "", v.strip())


class Login(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


class UrlIn(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def _u(cls, v):
        v = v.strip()
        if re.search(r"[\s<>\"']", v) or v.lower().startswith(("javascript:", "data:", "file:", "ftp:")): raise ValueError("Enter a plain web address without spaces")
        return v


class TextIn(BaseModel):
    text: str = Field(min_length=5, max_length=20000)


def public_user(u): return {"id": u["id"], "name": u["name"], "email": u["email"], "role": u.get("role", "user")}


def scan_doc(user, r: dict) -> dict:
    return {"user_id": user["id"], **{k: r[k] for k in ("input_type", "input", "verdict", "label", "threat_type", "risk_score", "confidence", "reasons", "recommendations", "signals", "adjustments", "details")}}


async def save(request: Request, user, result: dict):
    saved = await request.app.state.store.insert_scan(scan_doc(user, result))
    return {**result, "id": saved["id"], "created_at": saved["created_at"]}


# ---------- auth ----------
@app.post("/api/auth/register", status_code=201)
async def register(body: Register, request: Request):
    st = request.app.state.store
    if await st.get_user_by_email(body.email): raise HTTPException(409, "An account with this email already exists")
    u = await st.create_user({"email": body.email, "name": body.name, "password": hash_password(body.password), "role": "user"})
    return {"token": make_token(u["id"], "user"), "user": public_user(u)}


@app.post("/api/auth/login")
async def login(body: Login, request: Request):
    u = await request.app.state.store.get_user_by_email(body.email.strip().lower())
    if not u or not verify_password(body.password, u["password"]):
        log.warning("failed login for %s", body.email[:3] + "***")
        raise HTTPException(401, "Email or password is incorrect")
    return {"token": make_token(u["id"], u.get("role", "user")), "user": public_user(u)}


@app.get("/api/auth/me")
async def me(user=Depends(current_user)): return public_user(user)


# ---------- scanning ----------
@app.post("/api/scan/url")
async def scan_url(body: UrlIn, request: Request, user=Depends(current_user)):
    try: r = await analyze_url(body.url)
    except ValueError as e: raise HTTPException(422, str(e))
    return await save(request, user, r)


@app.post("/api/scan/website")
async def scan_website(body: UrlIn, request: Request, user=Depends(current_user)):
    try: r = await analyze_url(body.url, inspect_site=True)
    except ValueError as e: raise HTTPException(422, str(e))
    return await save(request, user, r)


@app.post("/api/scan/message")
async def scan_message(body: TextIn, request: Request, user=Depends(current_user)):
    return await save(request, user, await analyze_message(body.text, "message"))


@app.post("/api/scan/email")
async def scan_email(request: Request, body: TextIn | None = None, user=Depends(current_user)):
    return await save(request, user, await analyze_message(body.text, "email"))


@app.post("/api/scan/email/upload")
async def scan_email_file(request: Request, file: UploadFile = File(...), user=Depends(current_user)):
    name = (file.filename or "").lower()
    if not name.endswith((".eml", ".txt")): raise HTTPException(415, "Upload an .eml or .txt file")
    data = await file.read(1_000_001)
    if len(data) > 1_000_000: raise HTTPException(413, "File is larger than 1 MB")
    return await save(request, user, await analyze_message(data.decode("utf-8", "ignore")[:200_000], "email"))  # parsed as text only – never executed


@app.post("/api/extension/check")
async def extension_check(body: UrlIn, user=Depends(current_user)):
    """Lightweight endpoint for the browser extension – not stored in scan history, no page fetching."""
    r = await analyze_url(body.url)
    return {"verdict": r["verdict"], "risk_score": r["risk_score"], "confidence": r["confidence"], "threat_type": r["threat_type"], "reasons": [x["text"] for x in r["reasons"][:3]]}


# ---------- history & dashboard ----------
@app.get("/api/scans")
async def scans(request: Request, limit: int = Query(20, ge=1, le=100), skip: int = Query(0, ge=0), verdict: str | None = Query(None, pattern="^(SAFE|SUSPICIOUS|HIGH_RISK)$"),
                input_type: str | None = Query(None, pattern="^(url|website|message|email)$"), user=Depends(current_user)):
    items, total = await request.app.state.store.list_scans(user["id"], limit, skip, verdict, input_type)
    slim = [{k: s[k] for k in ("id", "input_type", "input", "verdict", "label", "threat_type", "risk_score", "confidence", "created_at")} | {"reasons": s["reasons"][:3]} for s in items]
    return {"items": slim, "total": total}


@app.get("/api/scans/{sid}")
async def scan_detail(sid: str, request: Request, user=Depends(current_user)):
    s = await request.app.state.store.get_scan(sid, user["id"])
    if not s: raise HTTPException(404, "Scan not found")
    return s


@app.delete("/api/scans/{sid}", status_code=204)
async def scan_delete(sid: str, request: Request, user=Depends(current_user)):
    if not await request.app.state.store.delete_scan(sid, user["id"]): raise HTTPException(404, "Scan not found")


@app.get("/api/dashboard")
async def dashboard(request: Request, user=Depends(current_user)):
    st = request.app.state.store
    recent, _ = await st.list_scans(user["id"], 6)
    stats = await st.user_stats(user["id"])
    tips = ["Turn on multi-factor authentication for email and banking.", "Banks never ask for OTPs or PINs over SMS, calls, or email.",
            "Type a company's address yourself instead of clicking links in messages.", "Check the domain spelling carefully – 'paypa1' is not 'paypal'."]
    return {**stats, "recent": [{k: s[k] for k in ("id", "input_type", "input", "verdict", "threat_type", "risk_score", "created_at")} for s in recent], "tips": tips}


# ---------- admin ----------
@app.get("/api/admin/overview")
async def admin_overview(request: Request, _=Depends(admin_user)):
    st = await request.app.state.store.admin_stats()
    metrics = {n: json.loads((ART / f"{n}_metrics.json").read_text()) for n in ("url", "text") if (ART / f"{n}_metrics.json").exists()}
    keys = {"VirusTotal": "VIRUSTOTAL_API_KEY", "URLhaus": "URLHAUS_AUTH_KEY", "Google Safe Browsing": "GOOGLE_SAFE_BROWSING_KEY"}
    return {**st, "models": metrics, "system": {
        "database": request.app.state.store.kind, "uptime_seconds": int(time.time() - STARTED), "url_model": url_ready(), "text_model": text_ready(),
        "live_checks": os.getenv("LIVE_NETWORK_CHECKS", "true").lower() == "true", "blocklist_entries": len([l for l in BLOCKLIST.read_text().splitlines() if l and not l.startswith("#")]) if BLOCKLIST.exists() else 0,
        "threat_intel": [{"name": n, "configured": bool(os.getenv(k))} for n, k in keys.items()]}}


@app.get("/api/health")
async def health(request: Request):
    return {"status": "ok", "database": request.app.state.store.kind, "models": url_ready() and text_ready()}
