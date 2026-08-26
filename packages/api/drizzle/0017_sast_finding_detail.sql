ALTER TABLE "sast_finding" ADD COLUMN "category" text DEFAULT 'ast' NOT NULL;--> statement-breakpoint
ALTER TABLE "sast_finding" ADD COLUMN "remediation" text DEFAULT '' NOT NULL;