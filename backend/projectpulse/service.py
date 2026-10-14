"""Framework-independent application service. Every method that touches user data takes the
authenticated owner id and enforces ownership through Store; the HTTP layer only maps errors."""
import datetime as dt, json
from urllib.parse import urlsplit
from .auth import *
from .compare import compare_audits
from .errors import *
from .pdf_export import build_pdf
from .presentation import build_presentation
from .quick_audit import run_quick_audit
from .ratelimit import RateLimiter
from .ssrf import validate_url, UnsafeURL

class Service:
    def __init__(self, store, secret, auditor=run_quick_audit, resolver=None, audits_per_hour=10, logins_per_15min=10, max_projects=25, token_ttl=3600, pw_iterations=ITER):
        self.store, self.secret, self.auditor, self.resolver = store, secret, auditor, resolver
        self.max_projects, self.token_ttl, self.pw_iter = max_projects, token_ttl, pw_iterations
        self.audit_limit = RateLimiter(audits_per_hour, 3600); self.login_limit = RateLimiter(logins_per_15min, 900)
        self._dummy = hash_password("dummy-password", pw_iterations)

    # auth
    def register(self, email, password):
        email = normalize_email(email); check_password_policy(password)
        try: uid = self.store.create_user(email, hash_password(password, self.pw_iter))
        except ValueError: raise Conflict("email already registered")
        return {"user_id": uid, "token": make_token(self.secret, uid, self.token_ttl)}
    def login(self, email, password, client_ip="unknown"):
        self.login_limit.check(f"ip:{client_ip}")
        email = (email or "").strip().lower(); self.login_limit.check(f"email:{email}")
        u = self.store.get_user_by_email(email)
        ok = verify_password(password or "", u["pw_hash"] if u else self._dummy)   # same work whether or not user exists
        if not (u and ok): raise AuthError("invalid credentials")
        return {"user_id": u["id"], "token": make_token(self.secret, u["id"], self.token_ttl)}
    def authenticate(self, token): return verify_token(self.secret, token or "")

    # projects
    def create_project(self, owner, name, url, authorized, **details):
        if authorized is not True: raise ValidationError("you must confirm you are authorized to analyze this target")
        if not (1 <= len((name or "").strip()) <= 120): raise ValidationError("name must be 1-120 characters")
        try: validate_url(url, **({"resolver": self.resolver} if self.resolver else {}))
        except UnsafeURL as e: raise ValidationError(f"url rejected: {e}")
        if self.store.count_projects(owner) >= self.max_projects: raise ValidationError("project quota reached")
        for k in ("description", "problem_statement", "target_users"):
            if details.get(k) is not None and len(details[k]) > 4000: raise ValidationError(f"{k} too long")
        try: return {"id": self.store.create_project(owner, name.strip(), url.strip(), **details)}
        except ValueError as e: raise ValidationError(str(e))
    def get_project(self, owner, pid): return self.store.get_project(owner, pid)
    def list_projects(self, owner, limit=20, offset=0): return self.store.list_projects(owner, limit, offset)

    # audits
    def run_audit(self, owner, pid):
        project = self.store.get_project(owner, pid)          # ownership check before anything else
        self.audit_limit.check(f"audit:{owner}")
        aid = self.store.start_audit(owner, pid); self.store.mark_running(aid)
        try: report = self.auditor(project["url"])
        except Exception as e:
            self.store.mark_failed(aid, f"audit crashed: {type(e).__name__}")
            return self.store.get_audit(owner, aid)
        self.store.complete_audit(aid, report); return self.store.get_audit(owner, aid)
    def get_audit(self, owner, aid): return self.store.get_audit(owner, aid)
    def list_audits(self, owner, pid, limit=20, offset=0): return self.store.list_audits(owner, pid, limit, offset)
    def compare(self, owner, a_id, b_id):
        a, b = self.store.get_audit(owner, a_id), self.store.get_audit(owner, b_id)
        if a["project_id"] != b["project_id"]: raise ValidationError("audits belong to different projects")
        if "completed" != a["status"] or "completed" != b["status"]: raise ValidationError("only completed audits can be compared")
        if a["attempt_no"] > b["attempt_no"]: a, b = b, a
        return {"earlier": a["id"], "later": b["id"], **compare_audits(a, b)}
    def set_finding_status(self, owner, aid, key, status): self.store.set_finding_status(owner, aid, key, status)

    # presentation + exports
    def _need_completed(self, owner, aid):
        a = self.store.get_audit(owner, aid)
        if a["status"] != "completed": raise ValidationError("audit is not completed")
        return a
    def generate_presentation(self, owner, aid):
        a = self._need_completed(owner, aid)
        content = build_presentation(self.store.get_project(owner, a["project_id"]), a, self.store.get_report(owner, aid))
        return {"id": self.store.save_presentation(owner, aid, content), "content": content}
    def get_presentation(self, owner, pid): return self.store.get_presentation(owner, pid)
    def latest_presentation(self, owner, aid): return self.store.latest_presentation(owner, aid)
    def export_pdf(self, owner, aid):
        a = self._need_completed(owner, aid)
        return build_pdf(self.store.get_project(owner, a["project_id"]), a, self.store.get_report(owner, aid))
    def export_json(self, owner, aid):
        a = self._need_completed(owner, aid)
        return {"audit": a, "report": self.store.get_report(owner, aid)}
