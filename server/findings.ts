// Derive findings from executed checks. Only failed/blocked checks become findings.
const FIXES: Record<string, string> = {
  "strict-transport-security": "Send `Strict-Transport-Security: max-age=31536000` from your host/CDN config.",
  "content-security-policy": "Add a Content-Security-Policy header restricting script/style sources.",
  "x-content-type-options": "Send `X-Content-Type-Options: nosniff`.",
  "referrer-policy": "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
};
const SEV = new Set(["critical", "high", "medium", "low", "info"]);
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

export interface Finding { key: string; title: string; category: string; severity: string; evidence: string; recommended_fix: string; status: string }

export function deriveFindings(checks: { name: string; status: string; severity: string; evidence: string; category?: string }[]): Finding[] {
  return checks.filter(c => c.status === "failed" || c.status === "blocked").map(c => {
    const category = c.category ?? "general";
    const fix = Object.entries(FIXES).find(([h]) => c.name.toLowerCase().includes(h))?.[1] ?? "Investigate the evidence and re-run the audit to verify the fix.";
    return { key: `${category}:${slug(c.name)}`, title: c.name, category, severity: SEV.has(c.severity) ? c.severity : "medium",
             evidence: c.evidence, recommended_fix: fix, status: "open" };
  });
}
