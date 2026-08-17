ALTER TABLE "scan" ADD COLUMN "source" text DEFAULT 'ci' NOT NULL;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "uploaded_by_user_id" uuid;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "uploaded_by_email" text;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "upload_note" text;--> statement-breakpoint
ALTER TABLE "scan" ADD CONSTRAINT "scan_uploaded_by_user_id_user_id_fk" FOREIGN KEY ("uploaded_by_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "scan_application_sha_idx" ON "scan" USING btree ("application_id","sbom_sha256");--> statement-breakpoint
CREATE INDEX "scan_source_idx" ON "scan" USING btree ("source","created_at" DESC NULLS LAST) WHERE "scan"."source" <> 'ci';