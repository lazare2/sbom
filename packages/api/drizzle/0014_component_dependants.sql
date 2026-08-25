ALTER TABLE "scan" ADD COLUMN "dependencies_extracted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "scan_component" ADD COLUMN "pulled_in_by" text[];--> statement-breakpoint
ALTER TABLE "scan_component" ADD COLUMN "pulled_in_by_count" integer;