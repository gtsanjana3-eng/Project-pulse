"""Transparent scoring engine. Scores come only from executed checks."""
from dataclasses import dataclass, field, asdict

SCORING_VERSION = "1.0.0"
MIN_CHECKS = 3  # fewer executed checks => "insufficient_evidence", never a score
DEFAULT_WEIGHTS = {
    "code_quality": 0.20, "security": 0.20, "performance": 0.15, "testing": 0.15,
    "accessibility": 0.10, "functionality": 0.10, "problem_alignment": 0.10,
}
SEVERITY_MULT = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5, "info": 0.25}
STATUSES = ("passed", "failed", "skipped", "blocked", "not_run")

@dataclass
class Check:
    name: str
    status: str                 # one of STATUSES
    severity: str = "medium"    # weight multiplier when failing/passing
    evidence: str = ""
    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"bad status {self.status}")

@dataclass
class CategoryScore:
    category: str
    score: float | None
    status: str                 # "scored" | "insufficient_evidence" | "not_evaluated"
    checks_run: int = 0
    checks_unavailable: int = 0
    confidence: str = "none"
    explanation: str = ""

def score_category(category, checks):
    run = [c for c in checks if c.status in ("passed", "failed")]
    unavailable = len(checks) - len(run)
    if not checks:
        return CategoryScore(category, None, "not_evaluated", 0, 0, "none", "No checks were available.")
    if len(run) < MIN_CHECKS:
        return CategoryScore(category, None, "insufficient_evidence", len(run), unavailable, "none",
                             f"Only {len(run)} check(s) executed; at least {MIN_CHECKS} required.")
    total = sum(SEVERITY_MULT[c.severity] for c in run)
    earned = sum(SEVERITY_MULT[c.severity] for c in run if c.status == "passed")
    conf = "high" if len(run) >= 10 else "medium" if len(run) >= 6 else "low"
    return CategoryScore(category, round(100 * earned / total, 2), "scored", len(run), unavailable, conf,
                         "score = severity-weighted share of executed checks that passed; "
                         "skipped/blocked/not-run checks are excluded, never counted as passed.")

def overall_score(categories, weights=None):
    weights = weights or DEFAULT_WEIGHTS
    scored = [c for c in categories if c.score is not None and weights.get(c.category, 0) > 0]
    if not scored:
        return {"score": None, "status": "insufficient_evidence", "effective_weights": {},
                "excluded": [c.category for c in categories], "scoring_version": SCORING_VERSION}
    tw = sum(weights[c.category] for c in scored)
    eff = {c.category: round(weights[c.category] / tw, 4) for c in scored}
    score = round(sum(c.score * eff[c.category] for c in scored), 2)
    return {"score": score, "status": "scored", "effective_weights": eff,
            "excluded": [c.category for c in categories if c not in scored],
            "scoring_version": SCORING_VERSION}
