"""Quick audit from a live URL using only what is observable over HTTP(S)."""
import http.client, socket, ssl, time
from urllib.parse import urljoin
from .ssrf import validate_url, UnsafeURL
from .scoring import Check, score_category, overall_score

MAX_BODY = 2_000_000
MAX_REDIRECTS = 5
SECURITY_HEADERS = {
    "strict-transport-security": "high", "content-security-policy": "medium",
    "x-content-type-options": "low", "referrer-policy": "low",
}

def fetch_pinned(url, resolver=None, timeout=10):
    """One request, no redirect following; connects to the validated IP."""
    kw = {"resolver": resolver} if resolver else {}
    p, host, port, ip = validate_url(url, **kw)
    sock = socket.create_connection((ip, port), timeout=timeout)
    if p.scheme == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.sock = sock
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    t0 = time.monotonic()
    conn.request("GET", path, headers={"Host": host, "User-Agent": "ProjectPulseAI/0.1", "Accept": "text/html,*/*"})
    r = conn.getresponse()
    body = r.read(MAX_BODY)
    ms = round((time.monotonic() - t0) * 1000)
    headers = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return {"status": r.status, "headers": headers, "bytes": len(body), "ms": ms}

def run_quick_audit(url, fetch=fetch_pinned, extra_checks=None):
    """extra_checks(url) -> {category: [Check]} lets the browser runner add evidence after reachability is confirmed."""
    chain, final, cur = [], None, url
    g = {"functionality": [], "security": [], "accessibility": []}
    try:
        for _ in range(MAX_REDIRECTS + 1):
            resp = fetch(cur)                      # fetch() re-validates every hop
            chain.append({"url": cur, "status": resp["status"]})
            if resp["status"] in (301, 302, 303, 307, 308) and "location" in resp["headers"]:
                cur = urljoin(cur, resp["headers"]["location"]); continue
            final = resp; break
        else:
            g["functionality"].append(Check("Redirect chain length", "failed", "medium", f"more than {MAX_REDIRECTS} redirects"))
    except UnsafeURL as e:
        g["functionality"].append(Check("URL safety", "blocked", "critical", str(e)))
    except (OSError, http.client.HTTPException) as e:
        g["functionality"].append(Check("Site reachable", "failed", "critical", f"{type(e).__name__}"))
    if final:
        ok = 200 <= final["status"] < 400
        g["functionality"] += [Check("Site reachable", "passed", "critical", f"HTTP {chain[-1]['status']}"),
                  Check("Final status is success", "passed" if ok else "failed", "high", f"HTTP {final['status']}"),
                  Check("Redirect chain short", "passed", "low", f"{len(chain)-1} redirect(s)"),
                  Check("Responds within 3s", "passed" if final["ms"] <= 3000 else "failed", "medium", f"{final['ms']} ms")]
        g["security"].append(Check("Served over HTTPS", "passed" if cur.startswith("https://") else "failed", "high", cur.split(":")[0]))
        for h, sev in SECURITY_HEADERS.items():
            has = h in final["headers"]
            g["security"].append(Check(f"Header {h}", "passed" if has else "failed", sev, "present" if has else "missing"))
        if extra_checks:
            try:
                for cat, cs in extra_checks(cur).items(): g.setdefault(cat, []).extend(cs)
            except Exception as e:
                g["functionality"].append(Check("Browser checks executed", "blocked", "low", f"{type(e).__name__}: {str(e)[:120]}"))
    cats = [score_category(k, v) for k, v in g.items()]
    cats += [score_category(c, []) for c in ("performance", "code_quality", "testing", "problem_alignment") if c not in g]
    return {"url": url, "redirects": chain, "categories": [c.__dict__ for c in cats], "overall": overall_score(cats),
            "checks": [dict(c.__dict__, category=k) for k, v in g.items() for c in v],
            "limitations": "A live URL cannot reveal source code, backend logic, private APIs or test coverage. "
                           "Lighthouse performance, source analysis and project tests are not part of this audit."}
