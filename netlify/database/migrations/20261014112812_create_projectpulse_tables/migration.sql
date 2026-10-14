CREATE TABLE "app_secrets" (
	"name" text PRIMARY KEY,
	"value" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"project_id" uuid NOT NULL,
	"owner_id" uuid NOT NULL,
	"attempt_no" integer NOT NULL,
	"status" text NOT NULL,
	"scoring_version" text,
	"overall" double precision,
	"effective_weights" jsonb,
	"report" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "uq_runs_project_attempt" UNIQUE("project_id","attempt_no")
);
--> statement-breakpoint
CREATE TABLE "category_scores" (
	"id" serial PRIMARY KEY,
	"audit_id" uuid NOT NULL,
	"category" text NOT NULL,
	"score" double precision,
	"status" text NOT NULL,
	"checks_run" integer NOT NULL,
	"confidence" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "findings" (
	"audit_id" uuid,
	"key" text,
	"title" text NOT NULL,
	"category" text NOT NULL,
	"severity" text NOT NULL,
	"evidence" text NOT NULL,
	"recommended_fix" text NOT NULL,
	"status" text NOT NULL,
	CONSTRAINT "findings_pkey" PRIMARY KEY("audit_id","key")
);
--> statement-breakpoint
CREATE TABLE "presentations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"audit_id" uuid NOT NULL,
	"owner_id" uuid NOT NULL,
	"content" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "projects" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"owner_id" uuid NOT NULL,
	"name" text NOT NULL,
	"url" text NOT NULL,
	"description" text,
	"problem_statement" text,
	"target_users" text,
	"features" jsonb DEFAULT '[]' NOT NULL,
	"tech_stack" jsonb DEFAULT '[]' NOT NULL,
	"repo_url" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rate_hits" (
	"id" serial PRIMARY KEY,
	"key" text NOT NULL,
	"at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"email" text NOT NULL UNIQUE,
	"pw_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "ix_runs_owner_created" ON "audit_runs" ("owner_id","created_at");--> statement-breakpoint
CREATE INDEX "ix_scores_audit" ON "category_scores" ("audit_id");--> statement-breakpoint
CREATE INDEX "ix_presentations_audit" ON "presentations" ("audit_id");--> statement-breakpoint
CREATE INDEX "ix_projects_owner" ON "projects" ("owner_id");--> statement-breakpoint
CREATE INDEX "ix_rate_hits_key_at" ON "rate_hits" ("key","at");--> statement-breakpoint
ALTER TABLE "audit_runs" ADD CONSTRAINT "audit_runs_project_id_projects_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id");--> statement-breakpoint
ALTER TABLE "audit_runs" ADD CONSTRAINT "audit_runs_owner_id_users_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "category_scores" ADD CONSTRAINT "category_scores_audit_id_audit_runs_id_fkey" FOREIGN KEY ("audit_id") REFERENCES "audit_runs"("id");--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_audit_id_audit_runs_id_fkey" FOREIGN KEY ("audit_id") REFERENCES "audit_runs"("id");--> statement-breakpoint
ALTER TABLE "presentations" ADD CONSTRAINT "presentations_audit_id_audit_runs_id_fkey" FOREIGN KEY ("audit_id") REFERENCES "audit_runs"("id");--> statement-breakpoint
ALTER TABLE "presentations" ADD CONSTRAINT "presentations_owner_id_users_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_owner_id_users_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id");