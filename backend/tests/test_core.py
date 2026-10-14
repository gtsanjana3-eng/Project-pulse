import unittest
from projectpulse.ssrf import validate_url, UnsafeURL
from projectpulse.scoring import Check, score_category, overall_score, CategoryScore
from projectpulse.quick_audit import run_quick_audit

pub = lambda h, p: ["93.184.216.34"]
def bad(ip): return lambda h, p: [ip]

class SSRF(unittest.TestCase):
    def test_blocks_private_targets(self):
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "100.64.0.1"]:
            with self.assertRaises(UnsafeURL, msg=ip): validate_url("http://x.example/", bad(ip))
    def test_any_private_answer_blocks(self):
        with self.assertRaises(UnsafeURL): validate_url("https://x.example/", lambda h, p: ["93.184.216.34", "10.0.0.1"])
    def test_scheme_creds_port(self):
        for u in ["file:///etc/passwd", "ftp://a.com", "http://u:p@a.com/", "http://a.com:22/", "http://"]:
            with self.assertRaises(UnsafeURL, msg=u): validate_url(u, pub)
    def test_public_ok(self):
        self.assertEqual(validate_url("https://app.vercel.app/x", pub)[3], "93.184.216.34")

class Scoring(unittest.TestCase):
    def mk(self, n, fail=0):
        return [Check(f"c{i}", "failed" if i < fail else "passed", "medium") for i in range(n)]
    def test_insufficient_not_zero(self):
        c = score_category("security", self.mk(2))
        self.assertIsNone(c.score); self.assertEqual(c.status, "insufficient_evidence")
    def test_empty_not_evaluated(self):
        self.assertEqual(score_category("testing", []).status, "not_evaluated")
    def test_skipped_never_passed(self):
        cs = self.mk(3) + [Check("s", "skipped"), Check("b", "blocked")]
        c = score_category("security", cs)
        self.assertEqual(c.score, 100.0); self.assertEqual(c.checks_run, 3); self.assertEqual(c.checks_unavailable, 2)
    def test_severity_weighting(self):
        cs = [Check("a", "failed", "critical"), Check("b", "passed", "low"), Check("c", "passed", "low")]
        self.assertEqual(score_category("security", cs).score, round(100 * 1 / 4, 2))
    def test_weight_normalization(self):
        cats = [CategoryScore("security", 80, "scored"), CategoryScore("performance", 60, "scored"),
                CategoryScore("testing", None, "not_evaluated")]
        o = overall_score(cats, {"security": 0.2, "performance": 0.2, "testing": 0.6})
        self.assertAlmostEqual(sum(o["effective_weights"].values()), 1.0, places=3)
        self.assertEqual(o["score"], 70.0); self.assertEqual(o["excluded"], ["testing"])
    def test_nothing_scored(self):
        self.assertIsNone(overall_score([CategoryScore("x", None, "not_evaluated")])["score"])

H = {"strict-transport-security": "x", "content-security-policy": "x", "x-content-type-options": "nosniff", "referrer-policy": "x"}
class QuickAudit(unittest.TestCase):
    def test_ok_site(self):
        r = run_quick_audit("https://a.com/", fetch=lambda u: {"status": 200, "headers": H, "bytes": 5, "ms": 100})
        self.assertEqual(r["overall"]["status"], "scored")
        self.assertEqual(r["overall"]["score"], 100.0)
        self.assertEqual(len(r["overall"]["excluded"]), 5)
    def test_unreachable(self):
        def f(u): raise TimeoutError()
        r = run_quick_audit("https://a.com/", fetch=f)
        self.assertIsNone(r["overall"]["score"])
    def test_redirect_to_internal_is_blocked(self):
        def f(u):
            if "a.com" in u: return {"status": 302, "headers": {"location": "http://169.254.169.254/"}, "bytes": 0, "ms": 1}
            validate_url(u, bad("169.254.169.254")); 
        r = run_quick_audit("https://a.com/", fetch=f)
        self.assertTrue(any(c["status"] == "blocked" for c in r["checks"]))
    def test_redirect_loop(self):
        r = run_quick_audit("https://a.com/", fetch=lambda u: {"status": 302, "headers": {"location": "/"}, "bytes": 0, "ms": 1})
        self.assertTrue(any(c["name"] == "Redirect chain length" for c in r["checks"]))
if __name__ == "__main__": unittest.main()
