import { doublePrecision, index, integer, jsonb, pgTable, primaryKey, serial, text, timestamp, unique, uuid } from "drizzle-orm/pg-core";

const createdAt = () => timestamp("created_at", { withTimezone: true }).notNull().defaultNow();

export const users = pgTable("users", {
  id: uuid().primaryKey().defaultRandom(),
  email: text().notNull().unique(),
  pwHash: text("pw_hash").notNull(),
  createdAt: createdAt(),
});

export const projects = pgTable("projects", {
  id: uuid().primaryKey().defaultRandom(),
  ownerId: uuid("owner_id").notNull().references(() => users.id),
  name: text().notNull(),
  url: text().notNull(),
  description: text(),
  problemStatement: text("problem_statement"),
  targetUsers: text("target_users"),
  features: jsonb().$type<string[]>().notNull().default([]),
  techStack: jsonb("tech_stack").$type<string[]>().notNull().default([]),
  repoUrl: text("repo_url"),
  createdAt: createdAt(),
}, t => [index("ix_projects_owner").on(t.ownerId)]);

export const auditRuns = pgTable("audit_runs", {
  id: uuid().primaryKey().defaultRandom(),
  projectId: uuid("project_id").notNull().references(() => projects.id),
  ownerId: uuid("owner_id").notNull().references(() => users.id),
  attemptNo: integer("attempt_no").notNull(),
  status: text().notNull(),
  scoringVersion: text("scoring_version"),
  overall: doublePrecision(),
  effectiveWeights: jsonb("effective_weights").$type<Record<string, number>>(),
  report: jsonb().$type<Record<string, any>>(),
  createdAt: createdAt(),
}, t => [unique("uq_runs_project_attempt").on(t.projectId, t.attemptNo), index("ix_runs_owner_created").on(t.ownerId, t.createdAt)]);

export const categoryScores = pgTable("category_scores", {
  id: serial().primaryKey(),
  auditId: uuid("audit_id").notNull().references(() => auditRuns.id),
  category: text().notNull(),
  score: doublePrecision(),
  status: text().notNull(),
  checksRun: integer("checks_run").notNull(),
  confidence: text().notNull(),
}, t => [index("ix_scores_audit").on(t.auditId)]);

export const findings = pgTable("findings", {
  auditId: uuid("audit_id").notNull().references(() => auditRuns.id),
  key: text().notNull(),
  title: text().notNull(),
  category: text().notNull(),
  severity: text().notNull(),
  evidence: text().notNull(),
  recommendedFix: text("recommended_fix").notNull(),
  status: text().notNull(),
}, t => [primaryKey({ columns: [t.auditId, t.key] })]);

export const presentations = pgTable("presentations", {
  id: uuid().primaryKey().defaultRandom(),
  auditId: uuid("audit_id").notNull().references(() => auditRuns.id),
  ownerId: uuid("owner_id").notNull().references(() => users.id),
  content: jsonb().$type<Record<string, any>>().notNull(),
  createdAt: createdAt(),
}, t => [index("ix_presentations_audit").on(t.auditId)]);

// Shared rate-limit counters: functions run on many instances, so in-process limits would not hold.
export const rateHits = pgTable("rate_hits", {
  id: serial().primaryKey(),
  key: text().notNull(),
  at: timestamp({ withTimezone: true }).notNull().defaultNow(),
}, t => [index("ix_rate_hits_key_at").on(t.key, t.at)]);

// Holds the auto-generated token signing secret when PP_SECRET is not configured.
export const appSecrets = pgTable("app_secrets", {
  name: text().primaryKey(),
  value: text().notNull(),
});
