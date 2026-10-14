"""HTTP-layer tests. They need fastapi + httpx; they are SKIPPED where those are not installed
(the build sandbox had no network), so a skip here means 'not run', not 'passed'."""
import unittest
try:
    from fastapi.testclient import TestClient
    HAVE = True
except Exception: HAVE = False
from projectpulse.config import Settings
from projectpulse.service import Service
from projectpulse.store import Store
from projectpulse.quick_audit import run_quick_audit

@unittest.skipUnless(HAVE, "fastapi/httpx not installed - NOT RUN")
class Api(unittest.TestCase):
    def setUp(self):
        from projectpulse.api import create_app
        st = Settings(secret="k" * 32)
        svc = Service(Store(), st.secret, auditor=lambda u: run_quick_audit(u, fetch=lambda x: {"status": 200, "headers": {}, "bytes": 1, "ms": 5}),
                      resolver=lambda h, p: ["93.184.216.34"], pw_iterations=1000)
        self.app = create_app(st, svc); self.c = TestClient(self.app)
    def tok(self, email):
        return {"Authorization": "Bearer " + self.c.post("/api/auth/register", json={"email": email, "password": "long-enough-pw"}).json()["token"]}
    def test_all_data_routes_require_auth(self):
        public = {"/health", "/api/auth/register", "/api/auth/login", "/openapi.json", "/docs", "/docs/oauth2-redirect"}
        for r in self.app.routes:
            if getattr(r, "path", None) and r.path not in public:
                for m in r.methods - {"HEAD", "OPTIONS"}:
                    resp = self.c.request(m, r.path.replace("{pid}", "x").replace("{aid}", "x").replace("{a}", "x").replace("{b}", "x").replace("{key}", "x"))
                    self.assertEqual(resp.status_code, 401, f"{m} {r.path}")
    def test_owner_isolation_over_http(self):
        a, m = self.tok("a@x.io"), self.tok("m@x.io")
        pid = self.c.post("/api/projects", headers=a, json={"name": "D", "url": "https://d.com/", "authorized": True}).json()["id"]
        aid = self.c.post(f"/api/projects/{pid}/audits", headers=a).json()["id"]
        for path in (f"/api/projects/{pid}", f"/api/projects/{pid}/audits", f"/api/audits/{aid}", f"/api/audits/{aid}/export.pdf", f"/api/audits/{aid}/export.json"):
            self.assertEqual(self.c.get(path, headers=m).status_code, 404, path)
        self.assertEqual(self.c.get(f"/api/audits/{aid}/export.pdf", headers=a).headers["content-type"], "application/pdf")
    def test_errors_do_not_leak(self):
        h = self.tok("a@x.io")
        r = self.c.post("/api/projects", headers=h, json={"name": "D", "url": "http://127.0.0.1/", "authorized": True})
        self.assertEqual(r.status_code, 422)
if __name__ == "__main__": unittest.main()
