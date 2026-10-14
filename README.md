# ProjectPulse AI

Audit a deployed project URL, get an evidence-based score, track improvements, and generate a project-specific presentation.

## Status (honest)
| Area | State |
|---|---|
| SSRF guard, scoring engine, quick audit (HTTP/HTTPS/headers/timing) | Implemented, unit-tested |
| SQLite store with versioned migrations, history, comparison, finding status rules | Implemented, tested (incl. restart persistence) |
| Auth (PBKDF2 + signed tokens), owner-level access control, rate limits, quotas | Implemented, tested at service layer |
| Presentation generator, Judge Q&A, PDF/JSON export | Implemented, tested |
| Playwright + axe runner with SSRF-guarded requests | Tested in real Chromium **with a stub axe file**; real axe-core not run |
| FastAPI HTTP layer | Written; its tests are **skipped unless fastapi+httpx are installed** |
| React dashboard (`frontend/`) | Source written; **not installed, built or run** |
| Lighthouse, source/GitHub deep audit, Celery, PostgreSQL/SQLAlchemy/Alembic | **Not implemented** (see below) |
Nothing is deployed.

## Run locally
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && playwright install chromium
npm i axe-core            # optional; gives node_modules/axe-core/axe.min.js
cp ../.env.example ../.env   # set PP_SECRET (and PP_AXE_PATH)
set -a; source ../.env; set +a
uvicorn projectpulse.api:app_factory --factory --reload      # http://localhost:8000/docs
# second terminal
cd ../frontend && npm install && npm run dev                 # http://localhost:5173
```
## Tests
```bash
cd backend && python -m unittest discover -s tests -v
```
Run in an environment with fastapi+httpx so `test_api.py` actually executes; a skip means "not run".

## Security notes
URL guard blocks non-http(s), credentials, odd ports, and any hostname resolving to a non-public address (all answers checked); the audit connects to the validated IP (anti-DNS-rebinding) and re-validates every redirect. In the browser every request is routed through the same guard. Localhost can only be reached by tests via an explicit `(literal IP, port)` allow-list argument that no config or request can set. Passwords: PBKDF2-SHA256 200k; tokens HMAC-signed, expiring. Rate limiting is in-process: use Redis-backed limits when running multiple workers.

## Migration path (not done)
- **PostgreSQL/SQLAlchemy/Alembic:** `store.py`'s public methods are the seam. Re-implement them with SQLAlchemy sessions; each entry of `MIGRATIONS` becomes one Alembic revision (`op.execute` the SQL, then convert to `op.create_table`).
- **Celery/Redis:** `Service.run_audit` currently runs inline; wrap its body in a task, return the `queued` audit id, and poll `GET /api/audits/{id}`.
- **Deep audit (GitHub/source):** needs sandboxed workers (no network, read-only FS) before running untrusted code; not started.

## Deployment (instructions only; not performed)
Backend: build `backend/Dockerfile`, run on any container host with a persistent volume for `PP_DB_PATH` (SQLite) or after the Postgres migration, set all `PP_*` variables as secrets, `PP_ENV=production`. Frontend: `npm run build`, host `dist/` (Vercel/Netlify) with `VITE_API_URL` pointing at the backend and add that origin to `PP_CORS_ORIGINS`. Verify with `GET /health`, then register, add a project, run an audit. Vercel serverless cannot run Playwright; keep the backend on container hosting.

## Live Demo

[Open ProjectPulse](https://project-pulse-3-eenl.onrender.com)
