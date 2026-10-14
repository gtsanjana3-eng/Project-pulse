"""Playwright + axe-core runner. Every request the page makes (navigation, subresources, redirects)
goes through the SSRF guard before it leaves the browser."""
from urllib.parse import urlsplit
from .scoring import Check
from .ssrf import validate_url, UnsafeURL
IMPACT = {"critical": "critical", "serious": "high", "moderate": "medium", "minor": "low", None: "low"}
LOCAL_SCHEMES = {"data", "blob", "about"}

def parse_axe(results):
    checks = []
    for v in results.get("violations", []):
        nodes = v.get("nodes", [])
        checks.append(Check(f'axe: {v["help"]}', "failed", IMPACT.get(v.get("impact"), "medium"),
                            f'{v["id"]}: {len(nodes)} element(s), e.g. {nodes[0]["target"][0] if nodes else "n/a"}'))
    for p in results.get("passes", []):
        checks.append(Check(f'axe: {p["help"]}', "passed", "medium", f'{p["id"]}: {len(p.get("nodes", []))} element(s)'))
    return checks

def _console(out, w):
    def h(m):
        if m.type == "error": out["console_errors"].append((w, m.text[:200]))
    return h
def _failed(out, w):
    def h(r):
        if r.url not in out["blocked"]: out["failed_requests"].append((w, r.url))
    return h

def run_browser_checks(url, axe_js_path, viewports=((1280, 800), (390, 844)), allow=frozenset(), no_sandbox=False, timeout_ms=20000):
    from playwright.sync_api import sync_playwright
    out = {"console_errors": [], "failed_requests": [], "blocked": [], "axe": [], "loaded": {}}
    with sync_playwright() as pw:
        b = pw.chromium.launch(args=["--no-sandbox"] if no_sandbox else [])
        try:
            for w, h in viewports:
                ctx = b.new_context(viewport={"width": w, "height": h}); page = ctx.new_page()
                def guard(route):
                    u = route.request.url
                    if urlsplit(u).scheme in LOCAL_SCHEMES: return route.continue_()
                    try: validate_url(u, allow=allow)
                    except UnsafeURL: out["blocked"].append(u); return route.abort()
                    route.continue_()
                page.route("**/*", guard)
                page.on("console", _console(out, w)); page.on("requestfailed", _failed(out, w))
                resp = page.goto(url, timeout=timeout_ms, wait_until="load")   # raises if the navigation itself is blocked
                out["loaded"][w] = resp.status if resp else None
                if w == viewports[0][0]:
                    page.add_script_tag(path=axe_js_path); out["axe"] = parse_axe(page.evaluate("axe.run()"))
                ctx.close()
        finally: b.close()
    return out

def to_checks(out):
    """Convert runner output into scored Checks; each only exists because it was actually measured."""
    c = {"functionality": [], "accessibility": list(out["axe"])}
    for w, st in out["loaded"].items():
        c["functionality"].append(Check(f"Page renders at {w}px width", "passed" if st and st < 400 else "failed", "high", f"HTTP {st}"))
    c["functionality"].append(Check("No JavaScript console errors", "failed" if out["console_errors"] else "passed", "medium",
                                    "; ".join(f"{w}px: {t}" for w, t in out["console_errors"][:3]) or "none observed"))
    c["functionality"].append(Check("No failed network requests", "failed" if out["failed_requests"] else "passed", "medium",
                                    "; ".join(u for _, u in out["failed_requests"][:3]) or "none observed"))
    if out["blocked"]:
        c["security"] = [Check("Page requests only public hosts", "failed", "medium", "page tried to reach non-public address: " + ", ".join(out["blocked"][:3]))]
    return c
