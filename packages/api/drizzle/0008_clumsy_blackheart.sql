CREATE TABLE "report_run" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"kind" text NOT NULL,
	"period_start" timestamp with time zone NOT NULL,
	"period_end" timestamp with time zone NOT NULL,
	"period_label" text NOT NULL,
	"time_zone" text NOT NULL,
	"generated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"generated_by_user_id" uuid,
	"generated_by_email" text,
	"baseline_run_id" uuid,
	"vuln_db_built_at" timestamp with time zone,
	"detail_level" text DEFAULT 'full' NOT NULL,
	"snapshot" jsonb NOT NULL,
	"pdf_blob_key" text,
	"sent_at" timestamp with time zone,
	"recipients" jsonb,
	"delivery_error" text
);
--> statement-breakpoint
ALTER TABLE "report_run" ADD CONSTRAINT "report_run_generated_by_user_id_user_id_fk" FOREIGN KEY ("generated_by_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "report_run_monthly_period_key" ON "report_run" USING btree ("kind","period_start") WHERE kind = 'monthly';--> statement-breakpoint
CREATE INDEX "report_run_generated_at_idx" ON "report_run" USING btree ("generated_at");