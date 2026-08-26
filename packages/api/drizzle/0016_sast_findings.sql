CREATE TABLE "sast_finding" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"run_id" uuid NOT NULL,
	"rule_id" text NOT NULL,
	"severity" text NOT NULL,
	"cwe" integer NOT NULL,
	"message" text NOT NULL,
	"file" text NOT NULL,
	"line" integer NOT NULL,
	"col" integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sast_run" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"application_id" uuid NOT NULL,
	"environment_id" uuid NOT NULL,
	"commit_sha" text,
	"branch" text,
	"ingest_token_name" text,
	"finding_count" integer DEFAULT 0 NOT NULL,
	"high_or_critical_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "sast_finding" ADD CONSTRAINT "sast_finding_run_id_sast_run_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."sast_run"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sast_run" ADD CONSTRAINT "sast_run_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sast_run" ADD CONSTRAINT "sast_run_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "sast_finding_run_idx" ON "sast_finding" USING btree ("run_id");--> statement-breakpoint
CREATE INDEX "sast_run_application_created_idx" ON "sast_run" USING btree ("application_id","created_at");--> statement-breakpoint
CREATE INDEX "sast_run_environment_idx" ON "sast_run" USING btree ("environment_id");