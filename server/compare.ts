// Compare two stored audits, only claiming deltas that are actually comparable.
import type { AuditView } from "./store.js";

export function compareAudits(a: AuditView, b: AuditView) { // a = earlier, b = later
  const notes: string[] = [];
  const ca = Object.fromEntries(a.categories.map(c => [c.category, c]));
  const cb = Object.fromEntries(b.categories.map(c => [c.category, c]));
  const compatible = a.scoring_version === b.scoring_version;
  if (!compatible) notes.push(`Scoring engine changed (${a.scoring_version} -> ${b.scoring_version}); score differences may not reflect real changes.`);
  const cats: Record<string, { before: number | null; after: number | null; delta: number | null }> = {};
  for (const name of [...new Set([...Object.keys(ca), ...Object.keys(cb)])].sort()) {
    const sa = ca[name]?.score ?? null, sb = cb[name]?.score ?? null;
    if (sa !== null && sb !== null) cats[name] = { before: sa, after: sb, delta: Math.round((sb - sa) * 100) / 100 };
    else if (sa !== sb) {
      cats[name] = { before: sa, after: sb, delta: null };
      notes.push(`${name}: evidence availability changed, so no point difference is reported.`);
    }
  }
  if (JSON.stringify(sortKeys(a.effective_weights)) !== JSON.stringify(sortKeys(b.effective_weights)))
    notes.push("Effective category weights differ between audits because different categories were evaluated.");
  const delta = a.overall !== null && b.overall !== null ? Math.round((b.overall - a.overall) * 100) / 100 : null;
  const fa = new Set(a.findings.map(f => f.key)), fb = new Set(b.findings.map(f => f.key));
  return {
    overall: { before: a.overall, after: b.overall, delta, comparable: compatible },
    categories: cats,
    findings: { resolved: [...fa].filter(k => !fb.has(k)).sort(), new: [...fb].filter(k => !fa.has(k)).sort(), remaining: [...fa].filter(k => fb.has(k)).sort() },
    notes,
  };
}
const sortKeys = (o: Record<string, number>) => Object.fromEntries(Object.entries(o).sort(([x], [y]) => x.localeCompare(y)));
