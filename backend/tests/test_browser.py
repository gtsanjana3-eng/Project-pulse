"""Real Chromium tests against a fixture server on 127.0.0.1. Localhost is reachable ONLY through the
explicit (literal-IP, port) `allow` argument that tests pass; production code never sets it."""
import http.server, os, tempfile, threading, unittest
from projectpulse.browser_checks import run_browser_checks, to_checks
from projectpulse.ssrf import validate_url, UnsafeURL

PAGE = b"""<!doctype html><html><head><title>t</title></head><body><h1>Fixture</h1>
<img src="http://169.254.169.254/latest/meta-data/x.png"><script>console.error("fixture-boom")</script></body></html>"""
AXE = "window.axe={run:async()=>({violations:[{id:'image-alt',help:'Images must have alternate text',impact:'critical',nodes:[{target:['img']}]}],passes:[{id:'html-has-lang',help:'html has lang',nodes:[{}]}]})};"

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(PAGE)
    def log_message(self, *a): pass

class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.tmp = tempfile.mkdtemp(); cls.axe = os.path.join(cls.tmp, "axe.stub.js")
        with open(cls.axe, "w") as f: f.write(AXE)
        cls.url = f"http://127.0.0.1:{cls.port}/"; cls.allow = frozenset({("127.0.0.1", cls.port)})
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close()

    def test_production_guard_still_blocks_localhost(self):
        with self.assertRaises(UnsafeURL): validate_url(self.url)                                   # default: blocked
        with self.assertRaises(UnsafeURL): validate_url("http://localhost:80/")
        with self.assertRaises(UnsafeURL): validate_url(self.url, allow=frozenset({("127.0.0.1", 1)}))   # wrong port: still blocked
        with self.assertRaises(UnsafeURL): validate_url(f"http://localhost:{self.port}/", allow=self.allow)  # hostnames never allowed
    def test_browser_refuses_localhost_without_allow(self):
        with self.assertRaises(Exception): run_browser_checks(self.url, self.axe, no_sandbox=True, timeout_ms=5000)
    def test_runner_collects_real_evidence(self):
        out = run_browser_checks(self.url, self.axe, allow=self.allow, no_sandbox=True)
        self.assertEqual(set(out["loaded"]), {1280, 390}); self.assertTrue(all(s == 200 for s in out["loaded"].values()))   # desktop + mobile
        self.assertTrue(any("fixture-boom" in t for _, t in out["console_errors"]))
        self.assertTrue(any("169.254.169.254" in u for u in out["blocked"]))                         # subresource SSRF blocked inside the browser
        self.assertEqual([(c.status, c.severity) for c in out["axe"]], [("failed", "critical"), ("passed", "medium")])
        c = to_checks(out); by = {x.name: x.status for x in c["functionality"]}
        self.assertEqual(by["No JavaScript console errors"], "failed"); self.assertEqual(by["Page renders at 390px width"], "passed")
        self.assertEqual(c["security"][0].status, "failed")
if __name__ == "__main__": unittest.main()
