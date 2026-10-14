"""HTTP layer: thin mapping from Service to FastAPI. All logic and access control live in service.py/store.py."""
import os
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .audit_pipeline import make_auditor
from .config import Settings, load_dotenv
from .errors import *
from .service import Service
from .store import Store

class Creds(BaseModel): email: str; password: str = Field(max_length=200)
class ProjectIn(BaseModel):
    name: str = Field(max_length=120); url: str = Field(max_length=2048); authorized: bool
    description: str | None = None; problem_statement: str | None = None; target_users: str | None = None
    features: list[str] = Field(default_factory=list, max_length=30); tech_stack: list[str] = Field(default_factory=list, max_length=30)
    repo_url: str | None = Field(default=None, max_length=2048)
class FindingIn(BaseModel): status: str

def create_app(settings: Settings | None = None, service: Service | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    svc = service or Service(Store(settings.db_path), settings.secret, auditor=make_auditor(settings),
                             audits_per_hour=settings.audits_per_hour, logins_per_15min=settings.logins_per_15min, max_projects=settings.max_projects_per_user)
    app = FastAPI(title="ProjectPulse AI", docs_url="/docs" if settings.env != "production" else None, redoc_url=None)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET", "POST", "PATCH"], allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def sec_headers(request, call_next):
        r = await call_next(request)
        r.headers.update({"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}); return r

    from fastapi.responses import JSONResponse
    STATUS = {NotFound: 404, ValidationError: 422, AuthError: 401, Conflict: 409, BadTransition: 409}
    def _mk(code):
        async def h(request, exc): return JSONResponse({"detail": str(exc) or type(exc).__name__}, code)
        return h
    for _cls, _code in STATUS.items(): app.add_exception_handler(_cls, _mk(_code))
    async def _rl(request, exc): return JSONResponse({"detail": "rate limit exceeded"}, 429, {"Retry-After": str(exc.retry_after)})
    app.add_exception_handler(RateLimited, _rl)

    def user(request: Request):
        h = request.headers.get("authorization", "")
        if not h.lower().startswith("bearer "): raise AuthError("missing bearer token")
        return svc.authenticate(h[7:])
    ip = lambda r: r.client.host if r.client else "unknown"

    @app.get("/health")
    def health(): return {"ok": True}
    @app.post("/api/auth/register", status_code=201)
    def register(b: Creds, request: Request): svc.login_limit.check(f"reg:{ip(request)}"); return svc.register(b.email, b.password)
    @app.post("/api/auth/login")
    def login(b: Creds, request: Request): return svc.login(b.email, b.password, ip(request))
    @app.post("/api/projects", status_code=201)
    def create_project(b: ProjectIn, u=Depends(user)):
        d = b.model_dump(); name, url, auth = d.pop("name"), d.pop("url"), d.pop("authorized")
        return svc.create_project(u, name, url, auth, **d)
    @app.get("/api/projects")
    def projects(limit: int = 20, offset: int = 0, u=Depends(user)): return svc.list_projects(u, limit, offset)
    @app.get("/api/projects/{pid}")
    def project(pid: str, u=Depends(user)): return svc.get_project(u, pid)
    @app.post("/api/projects/{pid}/audits", status_code=201)
    def run_audit(pid: str, u=Depends(user)): return svc.run_audit(u, pid)     # synchronous; move to Celery for long audits
    @app.get("/api/projects/{pid}/audits")
    def audits(pid: str, limit: int = 20, offset: int = 0, u=Depends(user)): return svc.list_audits(u, pid, limit, offset)
    @app.get("/api/audits/{aid}")
    def audit(aid: str, u=Depends(user)): return svc.get_audit(u, aid)
    @app.get("/api/audits/{a}/compare/{b}")
    def compare(a: str, b: str, u=Depends(user)): return svc.compare(u, a, b)
    @app.patch("/api/audits/{aid}/findings/{key}")
    def finding(aid: str, key: str, b: FindingIn, u=Depends(user)):
        try: svc.set_finding_status(u, aid, key, b.status)
        except ValueError as e: raise ValidationError(str(e))
        return {"ok": True}
    @app.post("/api/audits/{aid}/presentation", status_code=201)
    def gen_pres(aid: str, u=Depends(user)): return svc.generate_presentation(u, aid)
    @app.get("/api/audits/{aid}/presentation")
    def get_pres(aid: str, u=Depends(user)): return svc.latest_presentation(u, aid)
    @app.get("/api/audits/{aid}/export.json")
    def export_json(aid: str, u=Depends(user)): return svc.export_json(u, aid)
    @app.get("/api/audits/{aid}/export.pdf")
    def export_pdf(aid: str, u=Depends(user)):
        return Response(svc.export_pdf(u, aid), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="projectpulse-{aid}.pdf"'})
    return app

def app_factory():
    load_dotenv()
    return create_app()      # uvicorn projectpulse.api:app_factory --factory
