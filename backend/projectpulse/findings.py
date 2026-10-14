"""Derive findings from executed checks. Only failed/blocked checks become findings."""
import re
FIXES = {
    "strict-transport-security": "Send `Strict-Transport-Security: max-age=31536000` from your host/CDN config.",
    "content-security-policy": "Add a Content-Security-Policy header restricting script/style sources.",
    "x-content-type-options": "Send `X-Content-Type-Options: nosniff`.",
    "referrer-policy": "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
}
SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}

def slug(s): return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

def derive_findings(checks):
    out = []
    for c in checks:
        if c["status"] not in ("failed", "blocked"):
            continue
        key = f'{c.get("category","general")}:{slug(c["name"])}'
        fix = next((v for h, v in FIXES.items() if h in c["name"].lower()), "Investigate the evidence and re-run the audit to verify the fix.")
        out.append({"key": key, "title": c["name"], "category": c.get("category", "general"),
                    "severity": SEV.get(c["severity"], "medium"), "evidence": c["evidence"],
                    "recommended_fix": fix, "status": "open",
                    "verification": "Re-run an audit; this finding is only resolved when the check passes."})
    return out
