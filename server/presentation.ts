// Deterministic presentation generator grounded in project inputs + stored audit evidence.
// Anything the user did not supply or the audit did not measure becomes a [CONFIRM: ...] placeholder.
import type { AuditView, ProjectView } from "./store.js";

const WPM = 130;
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SHARE: Record<string, number> = { opening: .08, problem: .15, solution: .15, features: .20, technical: .15, demo: .10, results: .12, conclusion: .05 };
export const CATEGORY_LABEL: Record<string, string> = { code_quality: "Code quality", security: "Security", performance: "Performance", testing: "Testing",
  accessibility: "Accessibility", functionality: "Functionality", problem_alignment: "Problem alignment" };
const label = (c: string) => CATEGORY_LABEL[c] ?? c;
const f1 = (n: number) => n.toFixed(1);

type Facts = ReturnType<typeof facts>;
function facts(audit: AuditView, report: any) {
  const cats = Object.fromEntries(audit.categories.map(c => [c.category, c]));
  const scored = Object.entries(cats).filter(([, c]) => c.score !== null);
  const checks: any[] = report.checks ?? [];
  const run = checks.filter(c => c.status === "passed" || c.status === "failed");
  const open = audit.findings.filter(f => f.status !== "accepted_risk").sort((x, y) => SEV_ORDER.indexOf(x.severity) - SEV_ORDER.indexOf(y.severity));
  const reachable = checks.some(c => c.name === "Site reachable" && c.status === "passed");
  return { cats, scored, notEval: Object.keys(cats).filter(k => cats[k].score === null).sort(), checksRun: run.length, open, reachable, overall: audit.overall };
}

function sentPool(p: ProjectView, f: Facts) {
  const { name, url } = p; const needs: string[] = [];
  const need = (l: string) => { needs.push(l); return `[CONFIRM: ${l}]`; };
  const problem = p.problem_statement || need("add your problem statement");
  const users = p.target_users; const usersS = users ? `It is built for ${users}.` : need("add your target users");
  const desc = p.description || need("add a one-line project description");
  const feats = p.features ?? [], stack = p.tech_stack ?? [];
  const pool: Record<string, string[]> = {
    opening: [`Hello everyone, we are presenting ${name}.`, `${name} is deployed at ${url}.`],
    problem: [problem, usersS],
    solution: [desc],
    features: (feats.length ? feats.map(x => `A feature we built: ${x}.`) : [need("list your main features")])
      .concat(["These features are described by the team; the automated audit did not independently verify them."]),
    technical: (stack.length ? [`The team reports using ${stack.join(", ")}; this was not verified by the audit.`] : [need("list your technology stack")])
      .concat([`The automated audit ran ${f.checksRun} checks against the live site, covering availability, HTTPS and security headers.`])
      .concat(f.scored.map(([k, c]) => `${label(k)} scored ${f1(c.score!)} out of 100.`)),
    demo: [`For the demo we open ${url} first.`, ...feats.map(x => `Then we show: ${x}.`), "If the site is down, we switch to our recorded walkthrough."],
    results: [
      f.overall !== null ? `The audit gave an overall score of ${f1(f.overall)} out of 100, calculated only from the categories that could be evaluated.`
        : "The audit could not produce an overall score because there was not enough evidence.",
      f.open.length ? `The audit found ${f.open.length} open issue(s); the most serious is: ${f.open[0].title}.` : "The audit found no open issues in the checks that were run.",
      f.notEval.length ? `Not evaluated: ${f.notEval.map(label).join(", ")}.` : "",
      "A live-URL audit cannot see source code, backend logic or test coverage, so a good score is not proof of security or correctness.",
    ],
    conclusion: [
      `To summarise, ${name} ` + (users ? `addresses this problem for ${users}.` : "addresses this problem."),
      f.open.length ? `Our next step is to fix: ${f.open[0].recommended_fix}` : "Our next step is to expand testing with source-code analysis.",
      "Thank you. We are happy to take questions.",
    ],
  };
  for (const k of Object.keys(pool)) pool[k] = pool[k].filter(Boolean);
  return { pool, needs };
}

function script(pool: Record<string, string[]>, minutes: number) {
  const budget = minutes * WPM; const sections: { section: string; text: string }[] = []; let words = 0;
  for (const [sec, share] of Object.entries(SHARE)) {
    const quota = budget * share; let used = 0; const lines: string[] = [];
    for (const s of pool[sec]) {
      const n = s.split(/\s+/).filter(Boolean).length;
      if (lines.length && used + n > quota) break; // always keep first sentence of a section
      lines.push(s); used += n;
    }
    sections.push({ section: sec, text: lines.join(" ") }); words += used;
  }
  return { minutes, words, estimated_minutes: Math.round(words / WPM * 10) / 10, sections };
}

function slides(p: ProjectView, f: Facts, technical: boolean) {
  const sl: [string, string[], string][] = [
    ["Title", [p.name, p.description || "[CONFIRM: add description]"], "Logo or landing-page screenshot"],
    ["Problem", [p.problem_statement || "[CONFIRM: add problem statement]", `Users: ${p.target_users || "[CONFIRM]"}`], "One real-world photo or statistic you can cite"],
    ["Solution & features", p.features?.length ? [...p.features] : ["[CONFIRM: list features]"], "Screenshot of main workflow"],
    ["Live demo", [`Open ${p.url}`, "Walk through the features in order"], "Live site"],
    ["Audit results", [f.overall !== null ? `Overall: ${f1(f.overall)}/100` : "Overall: insufficient evidence",
      ...f.scored.map(([k, c]) => `${label(k)}: ${f1(c.score!)}`),
      ...(f.notEval.length ? [`Not evaluated: ${f.notEval.map(label).join(", ")}`] : [])], "Score bars from the dashboard"],
    ["Limitations & next steps", f.open.length ? f.open.slice(0, 3).map(x => x.title) : ["Expand tests with source-code analysis"], "Findings table"],
  ];
  if (technical) sl.splice(3, 0,
    ["Technology stack", [...(p.tech_stack?.length ? p.tech_stack : ["[CONFIRM: list stack]"]), "Declared by the team; not verified by the audit"], "Stack logo grid"],
    ["Architecture", ["[CONFIRM: no architecture evidence yet; connect the repository for a verified diagram]"], "Architecture diagram (only after verification)"],
    ["Security & testing", [`${f.checksRun} automated checks run`, ...f.open.slice(0, 4).map(x => `${x.title} (${x.severity})`)], "Findings screenshot"]);
  return sl.map(([title, bullets, visual]) => ({ title, bullets, visual, speaker_notes: `Explain: ${title}. Stay within what was verified.` }));
}

function qa(p: ProjectView, f: Facts) {
  const { cats } = f; const top = f.open;
  const st = (k: string) => { const c = cats[k]; return c && c.score !== null ? `${f1(c.score)}/100 from ${c.checks_run} checks` : "not evaluated"; };
  const a = (answer: string, confirm?: string[]) => ({ answer, needs_confirmation: confirm ?? [], grounded: !confirm?.length });
  const secIssues = top.filter(x => x.category === "security").map(x => x.title).join(", ") || "none found in the checks run";
  const q: [string, string, ReturnType<typeof a>][] = [
    ["Problem selection", "Why did you choose this problem?", p.problem_statement ? a(p.problem_statement) : a("", ["Why this problem matters to you and who is affected"])],
    ["Innovation", "What is new compared with existing solutions?", a("", ["Name two existing alternatives and what yours does differently"])],
    ["Technical architecture", "How is the system built?", p.tech_stack?.length ? a(`The team reports: ${p.tech_stack.join(", ")}. The audit did not verify this.`, ["Confirm the stack and data flow"]) : a("", ["Describe frontend, backend, database and data flow"])],
    ["AI usage", "Where do you use AI and why?", a("", ["Whether AI is used, which model/service, and what it does"])],
    ["Database and APIs", "What database and external APIs do you rely on?", a("", ["Database choice and external APIs; the live audit cannot observe them"])],
    ["Security", "How secure is it?", a(`The live audit security result is ${st("security")}. Open issues: ${secIssues}. This covers HTTPS and response headers only, not application logic.`)],
    ["Testing", "How did you test it?", a(`The automated audit ran ${f.checksRun} checks (functionality: ${st("functionality")}). Testing category: ${st("testing")}. We have not run project-specific tests unless you add them.`,
      cats.testing?.score != null ? undefined : ["Describe any tests you wrote or ran manually"])],
    ["Scalability", "Will it scale?", a("No load or scalability testing has been performed.", ["Hosting plan limits and any load testing you did"])],
    ["Limitations", "What are the limitations?", a([...f.notEval.map(k => `${label(k)} was not evaluated`), ...top.slice(0, 3).map(x => x.title)].join("; ")
      || "No limitations were detected by the checks run, but the audit cannot see source code or backend logic.")],
    ["Real-world usefulness", "Who would use this and why?", p.target_users ? a(`Intended users: ${p.target_users}.`) : a("", ["Target users and evidence of need (do not claim usage numbers you do not have)"])],
    ["Future development", "What would you do next?", a("Next steps from the audit: " + (top.length ? top.slice(0, 3).map(x => x.recommended_fix).join("; ") : "add source-code analysis and project tests."))],
  ];
  return q.map(([topic, question, an]) => ({ topic, question, ...an }));
}

export function buildPresentation(p: ProjectView, audit: AuditView, report: any) {
  const f = facts(audit, report);
  const { pool, needs } = sentPool(p, f);
  const feats = p.features ?? [];
  return {
    project: { name: p.name, url: p.url, audit_id: audit.id, attempt_no: audit.attempt_no, scoring_version: audit.scoring_version },
    introduction: { title: p.name, problem: p.problem_statement, target_users: p.target_users, solution: p.description },
    features: {
      declared: feats.map(x => ({ feature: x, status: "unverified", note: "Declared by you; the quick audit cannot confirm it. Demonstrate it live." })),
      verified_by_audit: f.reachable ? [{ item: "Deployed site is reachable", evidence: "HTTP check" }] : [],
    },
    technology: { declared_by_team_unverified: p.tech_stack ?? [], verified: [], note: "Stack detection requires source code; none was analysed." },
    architecture: { status: "insufficient_evidence", diagram: null, note: "No repository evidence; no diagram generated to avoid inventing components." },
    scripts: { three_minute: script(pool, 3), five_minute: script(pool, 5), ten_minute: script(pool, 10) },
    slides: { concise: slides(p, f, false), technical: slides(p, f, true) },
    judge_qa: qa(p, f),
    demo_plan: {
      order: [`Open ${p.url}`, ...(feats.length ? feats : ["[CONFIRM: list features to demo]"]).map(x => `Show: ${x}`), "Show the audit dashboard and open findings"],
      emphasize: ["What was measured vs. what is only claimed", "How the score was calculated and what was not evaluated"],
      backup_plan: "Keep a screen recording and screenshots of each demo step; if the site is down, narrate from them and say so.",
    },
    needs_confirmation: [...new Set(needs)].sort(),
  };
}
