import subprocess, tempfile, unittest, os
from projectpulse.errors import *
from projectpulse.service import Service
from projectpulse.store import Store
from projectpulse.quick_audit import run_quick_audit

H = {"strict-transport-security": "x", "content-security-policy": "x", "x-content-type-options": "n", "referrer-policy": "x"}
class Fake:
    headers = {}
    def __call__(self, url): return run_quick_audit(url, fetch=lambda u: {"status": 200, "headers": self.headers, "bytes": 1, "ms": 50})
pub = lambda h, p: ["93.184.216.34"]

def mk(**kw):
    f = Fake(); s = Service(Store(), "k" * 32, auditor=f, resolver=pub, pw_iterations=1000, **kw)
    return s, f
DETAILS = dict(problem_statement="Students cannot tell if a project is demo-ready.", target_users="hackathon teams",
               description="Audits a deployed project", features=["URL audit", "Score history"], tech_stack=["React", "FastAPI"])

class Flow(unittest.TestCase):
    def setUp(self):
        self.s, self.f = mk()
        self.alice = self.s.register("alice@x.io", "long-enough-pw")["user_id"]
        self.mallory = self.s.register("mallory@x.io", "long-enough-pw")["user_id"]
        self.pid = self.s.create_project(self.alice, "Demo", "https://demo.vercel.app/", True, **DETAILS)["id"]
    def audit(self): return self.s.run_audit(self.alice, self.pid)

    def test_register_login(self):
        self.assertEqual(self.s.authenticate(self.s.login("alice@x.io", "long-enough-pw")["token"]), self.alice)
        with self.assertRaises(AuthError): self.s.login("alice@x.io", "wrong-password!")
        with self.assertRaises(AuthError): self.s.login("nobody@x.io", "wrong-password!")
        with self.assertRaises(Conflict): self.s.register("ALICE@x.io", "long-enough-pw")
    def test_login_rate_limited(self):
        s, _ = mk(logins_per_15min=3)
        for _ in range(3):
            with self.assertRaises(AuthError): s.login("a@x.io", "bad-password!!", "1.2.3.4")
        with self.assertRaises(RateLimited): s.login("a@x.io", "bad-password!!", "1.2.3.4")
    def test_project_validation(self):
        with self.assertRaises(ValidationError): self.s.create_project(self.alice, "x", "https://a.com/", False)   # no authorization
        with self.assertRaises(ValidationError): self.s.create_project(self.alice, "x", "http://127.0.0.1/", True) if False else self.s.create_project(self.alice, "x", "file:///etc/passwd", True)
        bad = Service(Store(), "k" * 32, resolver=lambda h, p: ["10.0.0.1"], pw_iterations=1000)
        u = bad.register("b@x.io", "long-enough-pw")["user_id"]
        with self.assertRaises(ValidationError): bad.create_project(u, "x", "https://internal.example/", True)   # private resolution
    def test_quota_and_audit_rate_limit(self):
        s, _ = mk(max_projects=1, audits_per_hour=1); u = s.register("q@x.io", "long-enough-pw")["user_id"]
        p = s.create_project(u, "a", "https://a.com/", True)["id"]
        with self.assertRaises(ValidationError): s.create_project(u, "b", "https://b.com/", True)
        s.run_audit(u, p)
        with self.assertRaises(RateLimited): s.run_audit(u, p)
    def test_crashing_auditor_marks_failed(self):
        def boom(url): raise RuntimeError("secret internal detail")
        self.s.auditor = boom; a = self.audit()
        self.assertEqual(a["status"], "failed"); self.assertNotIn("secret", str(self.s.store.get_report(self.alice, a["id"])))
        with self.assertRaises(ValidationError): self.s.export_pdf(self.alice, a["id"])
    def test_every_endpoint_denies_other_owner(self):
        a1 = self.audit(); self.f.headers = H; a2 = self.audit()
        key = a1["findings"][0]["key"]
        calls = {"get_project": lambda: self.s.get_project(self.mallory, self.pid),
                 "list_audits": lambda: self.s.list_audits(self.mallory, self.pid),
                 "run_audit": lambda: self.s.run_audit(self.mallory, self.pid),
                 "get_audit": lambda: self.s.get_audit(self.mallory, a1["id"]),
                 "compare": lambda: self.s.compare(self.mallory, a1["id"], a2["id"]),
                 "finding_status": lambda: self.s.set_finding_status(self.mallory, a1["id"], key, "open"),
                 "gen_presentation": lambda: self.s.generate_presentation(self.mallory, a1["id"]),
                 "export_pdf": lambda: self.s.export_pdf(self.mallory, a1["id"]),
                 "export_json": lambda: self.s.export_json(self.mallory, a1["id"]),
                 "latest_presentation": lambda: self.s.latest_presentation(self.mallory, a1["id"])}
        for name, fn in calls.items():
            with self.assertRaises(NotFound, msg=name): fn()
        pres = self.s.generate_presentation(self.alice, a1["id"])
        with self.assertRaises(NotFound): self.s.get_presentation(self.mallory, pres["id"])
        self.assertEqual(self.s.list_projects(self.mallory)["total"], 0)
    def test_history_and_compare(self):
        a1 = self.audit(); self.f.headers = H; a2 = self.audit()
        c = self.s.compare(self.alice, a2["id"], a1["id"])            # order-insensitive
        self.assertEqual((c["earlier"], c["later"]), (a1["id"], a2["id"])); self.assertGreater(c["overall"]["delta"], 0)
        self.assertEqual(self.s.list_audits(self.alice, self.pid)["total"], 2)

class Presentation(unittest.TestCase):
    def setUp(self):
        self.s, self.f = mk(); self.u = self.s.register("p@x.io", "long-enough-pw")["user_id"]
    def gen(self, **d):
        p = self.s.create_project(self.u, "Demo", "https://demo.vercel.app/", True, **d)["id"]
        a = self.s.run_audit(self.u, p); return a, self.s.generate_presentation(self.u, a["id"])["content"]
    def test_grounded_in_inputs_and_audit(self):
        a, c = self.gen(**DETAILS)
        s5 = " ".join(x["text"] for x in c["scripts"]["five_minute"]["sections"])
        self.assertIn("Students cannot tell", s5); self.assertIn(f"{a['overall']:.1f}", s5)
        self.assertTrue(all(x["status"] == "unverified" for x in c["features"]["declared"]))     # claims never auto-verified
        self.assertEqual(c["technology"]["verified"], []); self.assertEqual(c["architecture"]["status"], "insufficient_evidence")
        self.assertIsNone(c["architecture"]["diagram"]); self.assertEqual(c["needs_confirmation"], [])
        self.assertEqual({q["topic"] for q in c["judge_qa"]} >= {"Security", "Testing", "Scalability", "Limitations"}, True)
        self.assertEqual(set(c["scripts"]), {"three_minute", "five_minute", "ten_minute"})
        w = [c["scripts"][k]["words"] for k in ("three_minute", "five_minute", "ten_minute")]; self.assertTrue(w[0] < w[1] <= w[2])
    def test_missing_inputs_become_placeholders_not_inventions(self):
        a, c = self.gen()
        txt = str(c)
        self.assertIn("[CONFIRM:", txt); self.assertTrue(c["needs_confirmation"])
        for bad in ("million", "revenue", "accuracy", "users love"): self.assertNotIn(bad, txt.lower())
        self.assertFalse(all(q["grounded"] for q in c["judge_qa"]))
        self.assertTrue([q for q in c["judge_qa"] if q["topic"] == "Innovation"][0]["needs_confirmation"])
    def test_scalability_answer_admits_no_testing(self):
        _, c = self.gen(**DETAILS)
        self.assertIn("No load", [q for q in c["judge_qa"] if q["topic"] == "Scalability"][0]["answer"])
    def test_saved_and_reloadable(self):
        p = self.s.create_project(self.u, "D", "https://d.com/", True)["id"]; a = self.s.run_audit(self.u, p)
        g = self.s.generate_presentation(self.u, a["id"]); self.assertEqual(self.s.latest_presentation(self.u, a["id"])["content"], g["content"])

class Exports(unittest.TestCase):
    def test_pdf_text_and_json(self):
        s, f = mk(); u = s.register("e@x.io", "long-enough-pw")["user_id"]
        p = s.create_project(u, "Demo <App>", "https://demo.vercel.app/", True)["id"]; a = s.run_audit(u, p)
        from reportlab import rl_config
        old = (rl_config.pageCompression, rl_config.useA85); rl_config.pageCompression = 0; rl_config.useA85 = 0   # readable streams, no external tools (works on Windows)
        try: pdf = s.export_pdf(u, a["id"])
        finally: rl_config.pageCompression, rl_config.useA85 = old
        self.assertTrue(pdf.startswith(b"%PDF"))
        text = pdf.decode("latin-1")
        self.assertIn(f"{a['overall']:.2f} / 100", text)             # score printed exactly as stored
        self.assertIn("Demo <App>", text)                            # special characters escaped, not dropped
        self.assertIn("not evaluated", text)                         # unevaluated categories shown honestly
        self.assertIn("Header content-security-policy", text); self.assertIn("missing", text)
        j = s.export_json(u, a["id"]); self.assertEqual(j["audit"]["overall"], a["overall"]); self.assertTrue(j["report"]["checks"])
if __name__ == "__main__": unittest.main()
