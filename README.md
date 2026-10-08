# CyberShield AI
**AI-Powered Cyber Threat Detection and Social Engineering Prevention Platform**

Paste a URL, website, SMS/chat message or email and get: **Safe / Suspicious / High-risk**, a **0–100 risk score**, **confidence %**, the **threat type**, plain-language **reasons**, and a **recommended action**. Every scan is saved to the user's cloud scan history.

```
User → React UI → (HTTPS) → FastAPI → URL ML · NLP model · Domain/Website analysis · Threat intel → Risk Engine → MongoDB Atlas
```

## Quick start (no Docker)
Requirements: Python 3.11+, Node 18+.

```bash
# 1. Backend (models are pre-trained; they retrain automatically if artifacts are missing)
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
cp .env.example .env                                      # edit secrets
uvicorn backend.app.main:app --reload --port 8000

# 2. Frontend (new terminal)
cd frontend && npm install && npm run dev                 # http://localhost:5173
```
Sign in as admin with `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env` (default `admin@cybershield.local` / `ChangeMe!2024` – **change it**), or register a normal user.
Without `MONGODB_URI` the app uses a local JSON file store so it works instantly; set the URI to use MongoDB Atlas.

## Docker
```bash
cp .env.example .env && docker compose up --build        # http://localhost:8080
```

## Folder map (matches the project brief)
| Folder | Purpose |
|---|---|
| `frontend/` | React + Vite UI: landing, auth, scanner, result page, history, dashboard, admin |
| `backend/` | FastAPI app: JWT auth, validation, rate limiting, security headers, REST API |
| `ml/` | Dataset generators, training scripts (LR / RF / XGBoost; TF-IDF + LR / NB / RF), saved models + metrics, SHAP report |
| `url_scanner/` | URL features, brand/typosquat detection, live DNS/TLS/RDAP/redirect/page checks, URL analysis pipeline |
| `nlp_detector/` | Social-engineering rules + ML, message & email pipeline, safe .eml parser |
| `threat_intelligence/` | VirusTotal, URLhaus, Google Safe Browsing, local blocklist (optional keys, graceful fallback) |
| `risk_engine/` | Configurable score fusion (`config.json`: thresholds, weights, overrides) |
| `database/` | MongoDB Atlas store + file-store fallback |
| `browser_extension/` | Manifest V3 extension – warns on dangerous sites, never auto-blocks |
| `docker/`, `docker-compose.yml` | Container images, nginx, compose stack |
| `docs/` | Architecture, ML, security, deployment guides |
| `tests/` | `pytest -q tests` |

## How scoring works
Signals (URL ML, security rules, domain/website analysis, threat intelligence, NLP model, NLP rules, embedded links, sender/attachments) are weighted, blended with the strongest signal, then adjusted by safety overrides (e.g. confirmed by threat-intel ⇒ ≥85, brand impersonation ⇒ ≥62, trusted domain ⇒ capped). Missing signals/APIs are simply dropped and weights re-normalised, so no single source decides alone.
Thresholds (default **0–30 SAFE, 31–60 SUSPICIOUS, 61–100 HIGH RISK**) live in `risk_engine/config.json`.

## Main API
`POST /api/auth/register|login` · `POST /api/scan/url|website|message|email` · `POST /api/scan/email/upload` · `GET /api/scans` · `GET /api/scans/{id}` · `GET /api/dashboard` · `GET /api/admin/overview` (admin) · `POST /api/extension/check` · Swagger UI: `/api/docs`

## Browser extension
Chrome/Edge → `chrome://extensions` → Developer mode → **Load unpacked** → select `browser_extension/`. Sign in from the popup (API address defaults to `http://localhost:8000`). A red banner appears only when a site is HIGH RISK **and** confidence ≥ 75%; pages are never blocked.

## Retraining with real data
Replace `ml/data/urls.csv` (`url,label`) and `ml/data/messages.csv` (`text,label`) with real datasets (Tranco, PhishTank, OpenPhish, URLhaus, SMS Spam Collection, Enron/phishing corpora), then run:
```bash
python -m ml.train_url_model && python -m ml.train_text_model && python -m ml.shap_report
```
**Honest note for your viva/report:** the bundled datasets are *synthetic* so the project runs offline; metrics therefore reflect synthetic data. Training on real data and reporting those numbers is strongly recommended – see `docs/ML.md`.

See `docs/` for architecture diagrams, cloud deployment (AWS/Azure/GCP + Atlas + HTTPS), and the security checklist.
