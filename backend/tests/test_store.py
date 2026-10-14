import unittest
from projectpulse.store import Store, NotFound, BadTransition
from projectpulse.compare import compare_audits
from projectpulse.quick_audit import run_quick_audit
from projectpulse.browser_checks import parse_axe

H = {"strict-transport-security": "x", "content-security-policy": "x", "x-content-type-options": "n", "referrer-policy": "x"}
def report(headers):
    return run_quick_audit("https://a.com/", fetch=lambda u: {"status": 200, "headers": headers, "bytes": 1, "ms": 50})

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(); self.pid = self.s.create_project("alice", "demo", "https://a.com/")
    def run_audit(self, headers, owner="alice"):
        a = self.s.start_audit(owner, self.pid); self.s.mark_running(a); self.s.complete_audit(a, report(headers)); return a
    def test_attempts_increment_and_persist(self):
        a1 = self.run_audit({}); a2 = self.run_audit(H)
        self.assertEqual(self.s.get_audit("alice", a1)["attempt_no"], 1)
        self.assertEqual(self.s.get_audit("alice", a2)["attempt_no"], 2)
        self.assertTrue(self.s.get_audit("alice", a1)["findings"])
    def test_access_control(self):
        a = self.run_audit(H)
        with self.assertRaises(NotFound): self.s.get_audit("mallory", a)
        with self.assertRaises(NotFound): self.s.start_audit("mallory", self.pid)
        with self.assertRaises(NotFound): self.s.list_audits("mallory", self.pid)
    def test_status_transitions(self):
        a = self.s.start_audit("alice", self.pid)
        with self.assertRaises(BadTransition): self.s.complete_audit(a, report(H))   # queued -> completed
        self.s.mark_failed(a, "timeout")
        with self.assertRaises(BadTransition): self.s.mark_running(a)
    def test_pagination_cap(self):
        for _ in range(3): self.run_audit(H)
        r = self.s.list_audits("alice", self.pid, limit=2, offset=0)
        self.assertEqual((r["total"], len(r["items"]), r["items"][0]["attempt_no"]), (3, 2, 3))
        self.assertEqual(self.s.list_audits("alice", self.pid, limit=10**6)["limit"], 100)
    def test_compare_improvement(self):
        a1 = self.run_audit({}); a2 = self.run_audit(H)
        c = compare_audits(self.s.get_audit("alice", a1), self.s.get_audit("alice", a2))
        self.assertGreater(c["overall"]["delta"], 0); self.assertTrue(c["findings"]["resolved"])
        self.assertEqual(c["findings"]["new"], []); self.assertGreater(c["categories"]["security"]["delta"], 0)
    def test_compare_version_mismatch_flagged(self):
        a1 = self.s.get_audit("alice", self.run_audit(H)); a2 = dict(self.s.get_audit("alice", self.run_audit(H)), scoring_version="2.0.0")
        c = compare_audits(a1, a2); self.assertFalse(c["overall"]["comparable"]); self.assertTrue(c["notes"])
    def test_compare_evidence_change_no_fake_delta(self):
        a = {"scoring_version": "1", "overall": 80, "effective_weights": {}, "findings": [], "categories": [{"category": "x", "score": 80}]}
        b = {"scoring_version": "1", "overall": 80, "effective_weights": {}, "findings": [], "categories": [{"category": "x", "score": None}]}
        self.assertIsNone(compare_audits(a, b)["categories"]["x"]["delta"])

class AxeTests(unittest.TestCase):
    def test_parse(self):
        r = {"violations": [{"id": "color-contrast", "help": "Contrast", "impact": "serious", "nodes": [{"target": ["#a"]}]}],
             "passes": [{"id": "html-has-lang", "help": "lang", "nodes": [{}]}]}
        cs = parse_axe(r)
        self.assertEqual([(c.status, c.severity) for c in cs], [("failed", "high"), ("passed", "medium")])
if __name__ == "__main__": unittest.main()
