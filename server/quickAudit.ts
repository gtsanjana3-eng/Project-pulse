// Quick audit from a live URL using only what is observable over HTTP(S).
import http from "node:http";
import https from "node:https";
import { validateUrl, UnsafeURL } from "./ssrf.js";
import { check, overallScore, scoreCategory, type Check } from "./scoring.js";

const MAX_BODY = 2_000_000;
const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 6000;
const SECURITY_HEADERS: Record<string, string> = {
  "strict-transport-security": "high", "content-security-policy": "medium",
  "x-content-type-options": "low", "referrer-policy": "low",
};

interface Fetched { status: number; headers: Record<string, string>; bytes: number; ms: number }

/** One request, no redirect following; connects to the validated IP. */
async function fetchPinned(raw: string): Promise<Fetched> {
  const v = await validateUrl(raw);
  const mod = v.url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    const req = mod.request({
      host: v.host, port: v.port, method: "GET", path: v.url.pathname + v.url.search, servername: v.host,
      lookup: (_h: string, opts: any, cb: any) => opts?.all ? cb(null, [{ address: v.ip, family: v.family }]) : cb(null, v.ip, v.family),
      headers: { Host: v.url.host, "User-Agent": "ProjectPulseAI/0.1", Accept: "text/html,*/*" },
      timeout: REQUEST_TIMEOUT_MS,
    }, res => {
      let bytes = 0;
      const done = () => {
        const headers: Record<string, string> = {};
        for (const [k, val] of Object.entries(res.headers)) if (val !== undefined) headers[k.toLowerCase()] = Array.isArray(val) ? val.join(", ") : val;
        resolve({ status: res.statusCode ?? 0, headers, bytes, ms: Math.round(performance.now() - t0) });
      };
      res.on("data", (c: Buffer) => { bytes += c.length; if (bytes >= MAX_BODY) { res.destroy(); done(); } });
      res.on("end", done);
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { name: "TimeoutError" })));
    req.on("error", reject);
    req.end();
  });
}

export async function runQuickAudit(url: string) {
  const chain: { url: string; status: number }[] = [];
  let final: Fetched | null = null, cur = url;
  const g: Record<string, Check[]> = { functionality: [], security: [], accessibility: [] };
  try {
    let i = 0;
    for (; i <= MAX_REDIRECTS; i++) {
      const resp = await fetchPinned(cur); // re-validates every hop
      chain.push({ url: cur, status: resp.status });
      if ([301, 302, 303, 307, 308].includes(resp.status) && resp.headers.location) { cur = new URL(resp.headers.location, cur).href; continue; }
      final = resp; break;
    }
    if (i > MAX_REDIRECTS) g.functionality.push(check("Redirect chain length", "failed", "medium", `more than ${MAX_REDIRECTS} redirects`));
  } catch (e) {
    if (e instanceof UnsafeURL) g.functionality.push(check("URL safety", "blocked", "critical", e.message));
    else g.functionality.push(check("Site reachable", "failed", "critical", (e as any)?.code ?? (e as Error)?.name ?? "Error"));
  }
  if (final) {
    const ok = final.status >= 200 && final.status < 400;
    g.functionality.push(
      check("Site reachable", "passed", "critical", `HTTP ${chain[chain.length - 1].status}`),
      check("Final status is success", ok ? "passed" : "failed", "high", `HTTP ${final.status}`),
      check("Redirect chain short", "passed", "low", `${chain.length - 1} redirect(s)`),
      check("Responds within 3s", final.ms <= 3000 ? "passed" : "failed", "medium", `${final.ms} ms`));
    g.security.push(check("Served over HTTPS", cur.startsWith("https://") ? "passed" : "failed", "high", cur.split(":")[0]));
    for (const [h, sev] of Object.entries(SECURITY_HEADERS)) {
      const has = h in final.headers;
      g.security.push(check(`Header ${h}`, has ? "passed" : "failed", sev, has ? "present" : "missing"));
    }
  }
  const cats = Object.entries(g).map(([k, v]) => scoreCategory(k, v));
  for (const c of ["performance", "code_quality", "testing", "problem_alignment"]) cats.push(scoreCategory(c, []));
  return {
    url, redirects: chain, categories: cats, overall: overallScore(cats),
    checks: Object.entries(g).flatMap(([category, v]) => v.map(c => ({ ...c, category }))),
    limitations: "A live URL cannot reveal source code, backend logic, private APIs or test coverage. "
      + "Lighthouse performance, browser accessibility checks, source analysis and project tests are not part of this audit.",
  };
}
export type AuditReport = Awaited<ReturnType<typeof runQuickAudit>>;
