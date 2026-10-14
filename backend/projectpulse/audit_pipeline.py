from .quick_audit import run_quick_audit
from .browser_checks import run_browser_checks, to_checks

def make_auditor(settings):
    """HTTP quick audit, plus browser/axe checks when PP_AXE_PATH points at axe.min.js."""
    if not settings.axe_path: return run_quick_audit
    def auditor(url):
        return run_quick_audit(url, extra_checks=lambda final_url: to_checks(
            run_browser_checks(final_url, settings.axe_path, no_sandbox=settings.browser_no_sandbox)))
    return auditor
