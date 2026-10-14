// Persistence layer on Netlify Database. Every read of user data is scoped by owner id;
// missing and foreign rows produce the same NotFound so existence is never leaked.
import { and, count, desc, eq, max } from "drizzle-orm";
import { db } from "../db/index.js";
import { auditRuns, categoryScores, findings, presentations, projects, users } from "../db/schema.js";
import { notFound, validation, conflict } from "./errors.js";
import { deriveFindings, type Finding } from "./findings.js";
import type { AuditReport } from "./quickAudit.js";

const MAX_PAGE = 100;
const USER_FINDING_STATUSES = ["accepted_risk", "open", "unverified"];
const TRANSITIONS: Record<string, string[]> = { queued: ["running", "failed"], running: ["completed", "failed"], completed: [], failed: [] };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const page = (limit: unknown, offset: unknown) => ({
  limit: Math.max(1, Math.min(Number.parseInt(String(limit ?? 20)) || 20, MAX_PAGE)),
  offset: Math.max(0, Number.parseInt(String(offset ?? 0)) || 0),
});
const isUuid = (s: string) => UUID_RE.test(s);

export interface ProjectView {
  id: string; name: string; url: string; description: string | null; problem_statement: string | null; target_users: string | null;
  features: string[]; tech_stack: string[]; repo_url: string | null; created_at: string;
}
export interface AuditView {
  id: string; project_id: string; attempt_no: number; status: string; scoring_version: string | null; overall: number | null; created_at: string;
  effective_weights: Record<string, number>;
  categories: { category: string; score: number | null; status: string; checks_run: number; confidence: string }[];
  findings: Finding[];
}

// users
export async function createUser(email: string, pwHash: string) {
  const [u] = await db.insert(users).values({ email, pwHash }).onConflictDoNothing().returning({ id: users.id });
  if (!u) throw conflict("email already registered");
  return u.id;
}
export async function getUserByEmail(email: string) {
  const [u] = await db.select().from(users).where(eq(users.email, email));
  return u ?? null;
}
export async function userExists(id: string) {
  if (!isUuid(id)) return false;
  const [u] = await db.select({ id: users.id }).from(users).where(eq(users.id, id));
  return !!u;
}

// projects
type ProjectRow = typeof projects.$inferSelect;
const projectView = (r: ProjectRow): ProjectView => ({
  id: r.id, name: r.name, url: r.url, description: r.description, problem_statement: r.problemStatement, target_users: r.targetUsers,
  features: r.features ?? [], tech_stack: r.techStack ?? [], repo_url: r.repoUrl, created_at: r.createdAt.toISOString(),
});
export interface ProjectDetails { description?: string | null; problem_statement?: string | null; target_users?: string | null; features?: string[]; tech_stack?: string[]; repo_url?: string | null }
export async function createProject(ownerId: string, name: string, url: string, d: ProjectDetails) {
  const [r] = await db.insert(projects).values({
    ownerId, name, url, description: d.description ?? null, problemStatement: d.problem_statement ?? null, targetUsers: d.target_users ?? null,
    features: d.features ?? [], techStack: d.tech_stack ?? [], repoUrl: d.repo_url ?? null,
  }).returning({ id: projects.id });
  return r.id;
}
async function projectRow(ownerId: string, pid: string) {
  const [r] = isUuid(pid) ? await db.select().from(projects).where(and(eq(projects.id, pid), eq(projects.ownerId, ownerId))) : [];
  if (!r) throw notFound("project not found");
  return r;
}
export const getProject = async (ownerId: string, pid: string) => projectView(await projectRow(ownerId, pid));
export async function countProjects(ownerId: string) {
  const [{ n }] = await db.select({ n: count() }).from(projects).where(eq(projects.ownerId, ownerId));
  return n;
}
export async function listProjects(ownerId: string, limitIn?: unknown, offsetIn?: unknown) {
  const { limit, offset } = page(limitIn, offsetIn);
  const rows = await db.select().from(projects).where(eq(projects.ownerId, ownerId)).orderBy(desc(projects.createdAt)).limit(limit).offset(offset);
  return { total: await countProjects(ownerId), limit, offset, items: rows.map(projectView) };
}

// audits
export async function startAudit(ownerId: string, projectId: string) {
  await projectRow(ownerId, projectId);
  for (let attempt = 0; ; attempt++) {
    const [{ m }] = await db.select({ m: max(auditRuns.attemptNo) }).from(auditRuns).where(eq(auditRuns.projectId, projectId));
    try {
      const [r] = await db.insert(auditRuns).values({ projectId, ownerId, attemptNo: (m ?? 0) + 1, status: "queued" }).returning({ id: auditRuns.id });
      return r.id;
    } catch (e) { if (attempt >= 3) throw e; } // concurrent start took the same attempt number; retry
  }
}
async function setStatus(aid: string, next: string, extra: Partial<typeof auditRuns.$inferInsert> = {}) {
  const [cur] = await db.select({ status: auditRuns.status }).from(auditRuns).where(eq(auditRuns.id, aid));
  if (!cur) throw notFound("audit not found");
  if (!TRANSITIONS[cur.status].includes(next)) throw conflict(`${cur.status} -> ${next}`);
  await db.update(auditRuns).set({ status: next, ...extra }).where(and(eq(auditRuns.id, aid), eq(auditRuns.status, cur.status)));
}
export const markRunning = (aid: string) => setStatus(aid, "running");
export const markFailed = (aid: string, reason: string) => setStatus(aid, "failed", { report: { error: reason } });
export async function completeAudit(aid: string, report: AuditReport) {
  const o = report.overall;
  if (report.categories.length)
    await db.insert(categoryScores).values(report.categories.map(c => ({ auditId: aid, category: c.category, score: c.score, status: c.status, checksRun: c.checks_run, confidence: c.confidence })));
  const fs = deriveFindings(report.checks);
  if (fs.length)
    await db.insert(findings).values(fs.map(f => ({ auditId: aid, key: f.key, title: f.title, category: f.category, severity: f.severity, evidence: f.evidence, recommendedFix: f.recommended_fix, status: f.status }))).onConflictDoNothing();
  await setStatus(aid, "completed", { scoringVersion: o.scoring_version, overall: o.score, effectiveWeights: o.effective_weights, report });
}
async function auditRow(ownerId: string, aid: string) {
  const [r] = isUuid(aid) ? await db.select().from(auditRuns).where(and(eq(auditRuns.id, aid), eq(auditRuns.ownerId, ownerId))) : [];
  if (!r) throw notFound("audit not found");
  return r;
}
async function auditView(r: typeof auditRuns.$inferSelect): Promise<AuditView> {
  const [cats, fnd] = await Promise.all([
    db.select({ category: categoryScores.category, score: categoryScores.score, status: categoryScores.status, checks_run: categoryScores.checksRun, confidence: categoryScores.confidence })
      .from(categoryScores).where(eq(categoryScores.auditId, r.id)).orderBy(categoryScores.id),
    db.select().from(findings).where(eq(findings.auditId, r.id)),
  ]);
  return {
    id: r.id, project_id: r.projectId, attempt_no: r.attemptNo, status: r.status, scoring_version: r.scoringVersion, overall: r.overall,
    created_at: r.createdAt.toISOString(), effective_weights: r.effectiveWeights ?? {}, categories: cats,
    findings: fnd.map(f => ({ key: f.key, title: f.title, category: f.category, severity: f.severity, evidence: f.evidence, recommended_fix: f.recommendedFix, status: f.status })),
  };
}
export const getAudit = async (ownerId: string, aid: string) => auditView(await auditRow(ownerId, aid));
export const getReport = async (ownerId: string, aid: string) => (await auditRow(ownerId, aid)).report ?? {};
export async function listAudits(ownerId: string, projectId: string, limitIn?: unknown, offsetIn?: unknown) {
  await projectRow(ownerId, projectId);
  const { limit, offset } = page(limitIn, offsetIn);
  const rows = await db.select().from(auditRuns).where(eq(auditRuns.projectId, projectId)).orderBy(desc(auditRuns.attemptNo)).limit(limit).offset(offset);
  const [{ n }] = await db.select({ n: count() }).from(auditRuns).where(eq(auditRuns.projectId, projectId));
  return { total: n, limit, offset, items: await Promise.all(rows.map(auditView)) };
}
export async function setFindingStatus(ownerId: string, aid: string, key: string, status: unknown) {
  await auditRow(ownerId, aid);
  if (status === "fixed") throw validation("'fixed' can only be established by a later audit in which the check passes");
  if (typeof status !== "string" || !USER_FINDING_STATUSES.includes(status)) throw validation(`status must be one of ${JSON.stringify(USER_FINDING_STATUSES)}`);
  const r = await db.update(findings).set({ status }).where(and(eq(findings.auditId, aid), eq(findings.key, key))).returning({ key: findings.key });
  if (!r.length) throw notFound("finding not found");
}

// presentations
export async function savePresentation(ownerId: string, aid: string, content: Record<string, any>) {
  await auditRow(ownerId, aid);
  const [r] = await db.insert(presentations).values({ auditId: aid, ownerId, content }).returning({ id: presentations.id });
  return r.id;
}
export async function latestPresentation(ownerId: string, aid: string) {
  await auditRow(ownerId, aid);
  const [r] = await db.select().from(presentations).where(and(eq(presentations.auditId, aid), eq(presentations.ownerId, ownerId))).orderBy(desc(presentations.createdAt)).limit(1);
  if (!r) throw notFound("presentation not found");
  return { id: r.id, audit_id: r.auditId, created_at: r.createdAt.toISOString(), content: r.content };
}
