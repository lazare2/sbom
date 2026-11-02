ALTER TABLE "component_vulnerability" ADD COLUMN "found_by" text[] DEFAULT '{}' NOT NULL;--> statement-breakpoint
ALTER TABLE "component_vulnerability" ADD COLUMN "source_details" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
-- Findings stored before merging came from one scanner: the component's provider at the time.
UPDATE "component_vulnerability" cv
   SET "found_by" = ARRAY[CASE WHEN c."vuln_provider" = 'xray' THEN 'xray' ELSE 'grype' END]
  FROM "component" c
 WHERE c."id" = cv."component_id"
   AND cv."found_by" = '{}';
