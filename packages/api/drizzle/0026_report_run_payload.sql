ALTER TABLE "report_run" ADD COLUMN "report" jsonb;--> statement-breakpoint
ALTER TABLE "report_run" ADD COLUMN "totals" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
/*
  Monthly reports now carry the analytics report rather than a snapshot to diff. Runs filed in
  the earlier format keep their stored PDF as the record; the one figure the history list shows
  for them, the application count, is copied out of the snapshot here, before the next
  migration drops it. The figures the old format did not measure stay absent rather than zero.
*/
UPDATE "report_run"
   SET "totals" = jsonb_build_object(
         'applications', COALESCE(("snapshot" -> 'totals' ->> 'applications')::int, 0),
         'legacyFindings', ("snapshot" -> 'totals' ->> 'findings')::int
       )
 WHERE "report" IS NULL;
