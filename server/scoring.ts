// Transparent scoring engine. Scores come only from executed checks.
export const SCORING_VERSION = "1.0.0";
const MIN_CHECKS = 3; // fewer executed checks => "insufficient_evidence", never a score
const DEFAULT_WEIGHTS: Record<string, number> = {
  code_quality: 0.20, security: 0.20, performance: 0.15, testing: 0.15,
  accessibility: 0.10, functionality: 0.10, problem_alignment: 0.10,
};
const SEVERITY_MULT: Record<string, number> = { critical: 3.0, high: 2.0, medium: 1.0, low: 0.5, info: 0.25 };

export type CheckStatus = "passed" | "failed" | "skipped" | "blocked" | "not_run";
export interface Check { name: string; status: CheckStatus; severity: string; evidence: string }
export interface CategoryScore {
  category: string; score: number | null; status: "scored" | "insufficient_evidence" | "not_evaluated";
  checks_run: number; checks_unavailable: number; confidence: string; explanation: string;
}
export interface Overall { score: number | null; status: string; effective_weights: Record<string, number>; excluded: string[]; scoring_version: string }

export const check = (name: string, status: CheckStatus, severity = "medium", evidence = ""): Check => ({ name, status, severity, evidence });
const r2 = (n: number) => Math.round(n * 100) / 100;

export function scoreCategory(category: string, checks: Check[]): CategoryScore {
  const run = checks.filter(c => c.status === "passed" || c.status === "failed");
  const unavailable = checks.length - run.length;
  if (!checks.length) return { category, score: null, status: "not_evaluated", checks_run: 0, checks_unavailable: 0, confidence: "none", explanation: "No checks were available." };
  if (run.length < MIN_CHECKS)
    return { category, score: null, status: "insufficient_evidence", checks_run: run.length, checks_unavailable: unavailable, confidence: "none",
             explanation: `Only ${run.length} check(s) executed; at least ${MIN_CHECKS} required.` };
  const total = run.reduce((s, c) => s + SEVERITY_MULT[c.severity], 0);
  const earned = run.filter(c => c.status === "passed").reduce((s, c) => s + SEVERITY_MULT[c.severity], 0);
  const confidence = run.length >= 10 ? "high" : run.length >= 6 ? "medium" : "low";
  return { category, score: r2(100 * earned / total), status: "scored", checks_run: run.length, checks_unavailable: unavailable, confidence,
           explanation: "score = severity-weighted share of executed checks that passed; skipped/blocked/not-run checks are excluded, never counted as passed." };
}

export function overallScore(categories: CategoryScore[], weights = DEFAULT_WEIGHTS): Overall {
  const scored = categories.filter(c => c.score !== null && (weights[c.category] ?? 0) > 0);
  if (!scored.length)
    return { score: null, status: "insufficient_evidence", effective_weights: {}, excluded: categories.map(c => c.category), scoring_version: SCORING_VERSION };
  const tw = scored.reduce((s, c) => s + weights[c.category], 0);
  const eff: Record<string, number> = {};
  for (const c of scored) eff[c.category] = Math.round(weights[c.category] / tw * 10000) / 10000;
  const score = r2(scored.reduce((s, c) => s + c.score! * eff[c.category], 0));
  return { score, status: "scored", effective_weights: eff, excluded: categories.filter(c => !scored.includes(c)).map(c => c.category), scoring_version: SCORING_VERSION };
}
