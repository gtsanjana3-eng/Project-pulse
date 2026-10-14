import os, tempfile, unittest
from projectpulse import auth
from projectpulse.config import Settings
from projectpulse.errors import *
from projectpulse.ratelimit import RateLimiter
from projectpulse.store import Store

class Auth(unittest.TestCase):
    def test_password_roundtrip(self):
        h = auth.hash_password("correct horse battery", iterations=1000)
        self.assertTrue(auth.verify_password("correct horse battery", h)); self.assertFalse(auth.verify_password("wrong", h))
        self.assertFalse(auth.verify_password("x", "garbage"))
    def test_token(self):
        t = auth.make_token("s" * 32, "u1", ttl=60, now=1000)
        self.assertEqual(auth.verify_token("s" * 32, t, now=1010), "u1")
        with self.assertRaises(AuthError): auth.verify_token("s" * 32, t, now=2000)       # expired
        with self.assertRaises(AuthError): auth.verify_token("o" * 32, t, now=1010)       # wrong key
        body, sig = t.split("."); forged = auth.make_token("s" * 32, "admin", now=1000).split(".")[0] + "." + sig
        with self.assertRaises(AuthError): auth.verify_token("s" * 32, forged, now=1010)  # tampered payload
        with self.assertRaises(AuthError): auth.verify_token("s" * 32, "junk")
    def test_validation(self):
        with self.assertRaises(ValidationError): auth.normalize_email("nope")
        with self.assertRaises(ValidationError): auth.check_password_policy("short")

class Limiter(unittest.TestCase):
    def test_window(self):
        t = [0]; r = RateLimiter(2, 10, clock=lambda: t[0])
        r.check("a"); r.check("a")
        with self.assertRaises(RateLimited) as cm: r.check("a")
        self.assertGreaterEqual(cm.exception.retry_after, 1); r.check("b")      # separate key
        t[0] = 11; r.check("a")                                                  # window slid

class Config(unittest.TestCase):
    def test_requires_secret(self):
        with self.assertRaises(ConfigError): Settings.from_env({})
        with self.assertRaises(ConfigError): Settings.from_env({"PP_SECRET": "x" * 32, "PP_CORS_ORIGINS": "*"})
        self.assertEqual(Settings.from_env({"PP_SECRET": "x" * 32}).cors_origins, ("http://localhost:5173",))

class DotEnv(unittest.TestCase):
    def test_loads_without_overriding(self):
        from projectpulse.config import load_dotenv
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with open(path, "w", encoding="utf-8") as f: f.write('# c\nPP_SECRET="' + "z" * 40 + '"\nPP_ENV=production\nBAD LINE\n')
            env = {"PP_ENV": "development"}; self.assertEqual(load_dotenv(path, env), path)
            self.assertEqual(env["PP_SECRET"], "z" * 40); self.assertEqual(env["PP_ENV"], "development")   # existing var wins
            self.assertIsNone(load_dotenv(os.path.join(d, "missing.env"), {}))

class Persistence(unittest.TestCase):
    def test_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.db")
            s = Store(path); uid = s.create_user("a@b.co", "h"); pid = s.create_project(uid, "demo", "https://a.com/", features=["login"], problem_statement="P")
            s.db.close()
            s2 = Store(path)  # new process simulation; migrations must be idempotent
            try:
                self.assertEqual(s2.get_project(uid, pid)["features"], ["login"])
                self.assertEqual(s2.get_user_by_email("a@b.co")["id"], uid)
                self.assertEqual(s2.db.execute("PRAGMA user_version").fetchone()[0], 1)
            finally:
                s2.close()
    def test_finding_status_rules(self):
        s = Store(); u = s.create_user("a@b.co", "h"); pid = s.create_project(u, "d", "https://a.com/")
        from projectpulse.quick_audit import run_quick_audit
        a = s.start_audit(u, pid); s.mark_running(a)
        s.complete_audit(a, run_quick_audit("https://a.com/", fetch=lambda x: {"status": 200, "headers": {}, "bytes": 1, "ms": 1}))
        key = s.get_audit(u, a)["findings"][0]["key"]
        with self.assertRaises(ValueError): s.set_finding_status(u, a, key, "fixed")
        s.set_finding_status(u, a, key, "accepted_risk")
        self.assertEqual([f for f in s.get_audit(u, a)["findings"] if f["key"] == key][0]["status"], "accepted_risk")
        with self.assertRaises(NotFound): s.set_finding_status("other", a, key, "open")
if __name__ == "__main__": unittest.main()
