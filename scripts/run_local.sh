#!/usr/bin/env bash
# One-command local dev: backend on :8000, frontend on :5173
set -e
cd "$(dirname "$0")/.."
[ -f .env ] || cp .env.example .env
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate && pip install -q -r backend/requirements.txt
(uvicorn backend.app.main:app --port 8000 &) 
cd frontend && npm install --no-audit --no-fund && npm run dev
