import { useEffect, useState } from "react";
import { Audit, Comparison, Page, Project, download, get, hasToken, patch, post, setToken } from "./api";

const LABEL: Record<string, string> = { code_quality: "Code Quality", security: "Security", performance: "Efficiency / Performance", testing: "Testing", accessibility: "Accessibility", functionality: "Functionality", problem_alignment: "Problem Alignment" };
const STATE: Record<string, string> = { not_evaluated: "Not evaluated", insufficient_evidence: "Insufficient evidence" };
const SEV: Record<string, string> = { critical: "bg-red-700 text-white", high: "bg-orange-600 text-white", medium: "bg-amber-500 text-black", low: "bg-sky-600 text-white", info: "bg-gray-500 text-white" };

const Bar = ({ value }: { value: number | null }) => (
  <div className="h-2 w-full rounded bg-gray-200" role="progressbar" aria-valuenow={value ?? undefined} aria-valuemin={0} aria-valuemax={100}>
    {value !== null && <div className="h-2 rounded bg-emerald-600" style={{ width: `${value}%` }} />}</div>);
const Card = ({ children, className = "" }: { children: React.ReactNode; className?: string }) => <section className={`rounded-xl border border-gray-200 bg-white p-4 shadow-sm ${className}`}>{children}</section>;
const Err = ({ msg }: { msg: string }) => msg ? <p role="alert" className="rounded bg-red-50 p-2 text-sm text-red-800">{msg}</p> : null;

function AuthForm({ onDone }: { onDone: () => void }) {
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [mode, setMode] = useState<"login" | "register">("login"); const [err, setErr] = useState("");
  const submit = async () => { try { const r = await post<{ token: string }>(`/api/auth/${mode}`, { email, password }); setToken(r.token); onDone(); } catch (e) { setErr((e as Error).message); } };
  return (<Card className="mx-auto mt-16 max-w-sm space-y-3"><h1 className="text-xl font-semibold">ProjectPulse AI</h1>
    <input className="w-full rounded border p-2" placeholder="Email" aria-label="Email" value={email} onChange={e => setEmail(e.target.value)} />
    <input className="w-full rounded border p-2" type="password" placeholder="Password (10+ characters)" aria-label="Password" value={password} onChange={e => setPassword(e.target.value)} />
    <Err msg={err} /><button className="w-full rounded bg-gray-900 p-2 text-white" onClick={submit}>{mode === "login" ? "Log in" : "Create account"}</button>
    <button className="text-sm underline" onClick={() => setMode(mode === "login" ? "register" : "login")}>{mode === "login" ? "Need an account?" : "Have an account?"}</button></Card>);
}

function NewProject({ onCreated }: { onCreated: (p: Project) => void }) {
  const [f, setF] = useState({ name: "", url: "", problem_statement: "", description: "", target_users: "", features: "" }); const [auth, setAuth] = useState(false); const [err, setErr] = useState("");
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  const go = async () => { try { const r = await post<{ id: string }>("/api/projects", { ...f, features: f.features.split("\n").map(s => s.trim()).filter(Boolean), authorized: auth }); onCreated({ id: r.id, name: f.name, url: f.url }); } catch (e) { setErr((e as Error).message); } };
  return (<Card className="space-y-2"><h2 className="font-semibold">New project</h2>
    <input className="w-full rounded border p-2" placeholder="Project name" aria-label="Project name" value={f.name} onChange={set("name")} />
    <input className="w-full rounded border p-2" placeholder="https://your-app.vercel.app" aria-label="Deployed URL" value={f.url} onChange={set("url")} />
    <textarea className="w-full rounded border p-2" placeholder="Problem statement (needed for a meaningful presentation)" value={f.problem_statement} onChange={set("problem_statement")} />
    <textarea className="w-full rounded border p-2" placeholder="Description" value={f.description} onChange={set("description")} />
    <input className="w-full rounded border p-2" placeholder="Target users" value={f.target_users} onChange={set("target_users")} />
    <textarea className="w-full rounded border p-2" placeholder="Features, one per line" value={f.features} onChange={set("features")} />
    <label className="flex gap-2 text-sm"><input type="checkbox" checked={auth} onChange={e => setAuth(e.target.checked)} />I am authorized to analyze this website.</label>
    <Err msg={err} /><button className="rounded bg-gray-900 px-4 py-2 text-white disabled:opacity-40" disabled={!auth || !f.name || !f.url} onClick={go}>Save project</button></Card>);
}

function Report({ a, reload }: { a: Audit; reload: () => void }) {
  const [err, setErr] = useState("");
  const setStatus = async (key: string, status: string) => { try { await patch(`/api/audits/${a.id}/findings/${encodeURIComponent(key)}`, { status }); reload(); } catch (e) { setErr((e as Error).message); } };
  return (<div className="space-y-4"><Card><div className="flex flex-wrap items-end justify-between gap-2"><div><p className="text-sm text-gray-500">AI Evaluation Score · attempt {a.attempt_no} · {new Date(a.created_at).toLocaleString()} · engine v{a.scoring_version}</p>
    <p className="text-4xl font-bold">{a.overall === null ? "Insufficient evidence" : <>{a.overall.toFixed(2)} <span className="text-lg text-gray-500">/ 100</span></>}</p></div>
    <div className="space-x-2"><button className="rounded border px-3 py-1" onClick={() => download(`/api/audits/${a.id}/export.pdf`, "report.pdf").catch(e => setErr(e.message))}>PDF</button>
    <button className="rounded border px-3 py-1" onClick={() => download(`/api/audits/${a.id}/export.json`, "report.json").catch(e => setErr(e.message))}>JSON</button></div></div>
    <Bar value={a.overall} /><p className="mt-2 text-xs text-gray-600">Weights used: {Object.entries(a.effective_weights).map(([k, v]) => `${LABEL[k] ?? k} ${(v * 100).toFixed(0)}%`).join(", ") || "none"}. Unevaluated categories are excluded, not scored zero. A high score does not prove the app is secure or error-free.</p></Card>
    <Err msg={err} />
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{a.categories.map(c => (<Card key={c.category}><p className="font-medium">{LABEL[c.category] ?? c.category}</p>
      <p className="text-2xl font-semibold">{c.score === null ? STATE[c.status] ?? c.status : c.score.toFixed(1)}</p><Bar value={c.score} />
      <p className="mt-1 text-xs text-gray-600">{c.checks_run} checks run · confidence {c.confidence}</p></Card>))}</div>
    <Card><h3 className="mb-2 font-semibold">Findings</h3>{a.findings.length === 0 ? <p className="text-sm">No findings in the checks that were run.</p> :
      <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Fix</th><th>Status</th></tr></thead><tbody>
        {a.findings.map(f => (<tr key={f.key} className="border-t align-top"><td className="py-2"><span className={`rounded px-2 py-0.5 text-xs ${SEV[f.severity]}`}>{f.severity}</span></td><td>{f.title}</td><td>{f.evidence}</td><td>{f.recommended_fix}</td>
          <td><select aria-label={`Status for ${f.title}`} value={f.status} onChange={e => setStatus(f.key, e.target.value)}><option value="open">Open</option><option value="accepted_risk">Accepted risk</option><option value="unverified">Unverified</option></select>
            <p className="text-xs text-gray-500">Fixed is set only by a later passing audit.</p></td></tr>))}</tbody></table></div>}</Card></div>);
}

function Presentation({ audit }: { audit: Audit }) {
  const [p, setP] = useState<any>(null); const [err, setErr] = useState(""); const [len, setLen] = useState("five_minute");
  const gen = async () => { try { setP((await post<{ content: any }>(`/api/audits/${audit.id}/presentation`)).content); } catch (e) { setErr((e as Error).message); } };
  return (<Card className="space-y-3"><div className="flex items-center justify-between"><h3 className="font-semibold">Presentation</h3><button className="rounded bg-gray-900 px-3 py-1 text-white" onClick={gen}>Generate from this audit</button></div><Err msg={err} />
    {p && <>{p.needs_confirmation.length > 0 && <p className="rounded bg-amber-50 p-2 text-sm">Needs your input: {p.needs_confirmation.join("; ")}</p>}
      <select aria-label="Script length" value={len} onChange={e => setLen(e.target.value)}><option value="three_minute">3 minutes</option><option value="five_minute">5 minutes</option><option value="ten_minute">10 minutes</option></select>
      <button className="ml-2 text-sm underline" onClick={() => navigator.clipboard.writeText(p.scripts[len].sections.map((s: any) => s.text).join("\n\n"))}>Copy script</button>
      {p.scripts[len].sections.map((s: any) => <div key={s.section}><h4 className="text-sm font-semibold capitalize">{s.section}</h4><p className="text-sm">{s.text}</p></div>)}
      <h4 className="font-semibold">Judge Q&A</h4>{p.judge_qa.map((q: any) => <details key={q.topic} className="text-sm"><summary>{q.question}</summary><p>{q.answer}</p>{q.needs_confirmation.length > 0 && <p className="text-amber-700">Confirm: {q.needs_confirmation.join("; ")}</p>}</details>)}</>}</Card>);
}

export default function App() {
  const [authed, setAuthed] = useState(hasToken()); const [projects, setProjects] = useState<Project[]>([]); const [sel, setSel] = useState<Project | null>(null);
  const [audits, setAudits] = useState<Audit[]>([]); const [cur, setCur] = useState<Audit | null>(null); const [busy, setBusy] = useState(false); const [err, setErr] = useState(""); const [cmp, setCmp] = useState<Comparison | null>(null);
  const loadProjects = () => get<Page<Project>>("/api/projects").then(r => setProjects(r.items)).catch(e => { setErr(e.message); if (/token|401|invalid/i.test(e.message)) { setToken(null); setAuthed(false); } });
  const loadAudits = (p: Project) => get<Page<Audit>>(`/api/projects/${p.id}/audits`).then(r => { setAudits(r.items); setCur(c => r.items.find(x => x.id === c?.id) ?? r.items[0] ?? null); }).catch(e => setErr(e.message));
  useEffect(() => { if (authed) loadProjects(); }, [authed]);
  useEffect(() => { if (sel) { setCmp(null); loadAudits(sel); } }, [sel]);
  const run = async () => { if (!sel) return; setBusy(true); setErr(""); try { const a = await post<Audit>(`/api/projects/${sel.id}/audits`); setCur(a); await loadAudits(sel); } catch (e) { setErr((e as Error).message); } setBusy(false); };
  const compare = async (a: Audit, b: Audit) => { try { setCmp(await get<Comparison>(`/api/audits/${a.id}/compare/${b.id}`)); } catch (e) { setErr((e as Error).message); } };
  if (!authed) return <AuthForm onDone={() => setAuthed(true)} />;
  return (<div className="mx-auto max-w-6xl space-y-4 p-4"><header className="flex items-center justify-between"><h1 className="text-xl font-bold">ProjectPulse AI</h1><button className="text-sm underline" onClick={() => { setToken(null); setAuthed(false); }}>Log out</button></header>
    <Err msg={err} />
    <div className="grid gap-4 lg:grid-cols-[18rem_1fr]"><aside className="space-y-3"><Card><h2 className="mb-2 font-semibold">Projects</h2>{projects.length === 0 && <p className="text-sm text-gray-500">No projects yet.</p>}
      {projects.map(p => <button key={p.id} className={`block w-full rounded p-2 text-left text-sm ${sel?.id === p.id ? "bg-gray-900 text-white" : "hover:bg-gray-100"}`} onClick={() => setSel(p)}>{p.name}<br /><span className="text-xs opacity-70">{p.url}</span></button>)}</Card>
      <NewProject onCreated={p => { loadProjects(); setSel(p); }} /></aside>
      <main className="space-y-4">{!sel ? <Card>Select or create a project to begin.</Card> : <>
        <Card className="flex items-center justify-between"><div><h2 className="font-semibold">{sel.name}</h2><p className="text-sm text-gray-500">{sel.url}</p></div><button className="rounded bg-emerald-700 px-4 py-2 text-white disabled:opacity-50" disabled={busy} onClick={run}>{busy ? "Analyzing…" : "Analyze My Project"}</button></Card>
        {cur && cur.status === "completed" && <Report a={cur} reload={() => loadAudits(sel)} />}{cur && cur.status === "failed" && <Err msg="This audit failed. Try again." />}
        {audits.length === 0 && !busy && <Card>No audits yet. Run the first one.</Card>}
        {audits.length > 0 && <Card><h3 className="mb-2 font-semibold">Attempt history</h3><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr><th>#</th><th>Date</th><th>Overall</th><th>Status</th><th></th></tr></thead><tbody>
          {audits.map((a, i) => <tr key={a.id} className="border-t"><td>{a.attempt_no}</td><td>{new Date(a.created_at).toLocaleString()}</td><td>{a.overall === null ? "n/a" : a.overall.toFixed(2)}</td><td>{a.status}</td>
            <td className="space-x-2"><button className="underline" onClick={() => setCur(a)}>Open</button>{audits[i + 1] && <button className="underline" onClick={() => compare(audits[i + 1], a)}>Compare with previous</button>}</td></tr>)}</tbody></table></div>
          {cmp && <div className="mt-3 rounded bg-gray-50 p-3 text-sm"><p className="font-medium">{cmp.overall.delta === null ? "Overall change not computable" : `Overall change: ${cmp.overall.delta > 0 ? "+" : ""}${cmp.overall.delta} points (${cmp.overall.before} → ${cmp.overall.after})`}</p>
            <p>Resolved: {cmp.findings.resolved.length} · New: {cmp.findings.new.length} · Remaining: {cmp.findings.remaining.length}</p>{cmp.notes.map(n => <p key={n} className="text-amber-700">{n}</p>)}</div>}</Card>}
        {cur && cur.status === "completed" && <Presentation audit={cur} />}</>}</main></div></div>);
}
