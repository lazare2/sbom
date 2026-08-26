/*
  Environments: isolated estates, with everything existing moved into "Production".

  Hand-written rather than used as generated. drizzle-kit emits
  `ADD COLUMN environment_id uuid NOT NULL` for eight tables, which aborts on any
  database that already holds a row -- so the column arrives nullable, is filled,
  and only then becomes NOT NULL.

  Two decisions are made here rather than in code, because getting them wrong is
  silent:

    1. Existing ingest tokens are bound to Production. A NULL environment on a
       token means "super token: may write anywhere, must name an estate on every
       upload". Leaving the existing rows NULL would convert every pipeline
       credential into one of those at once, and every current pipeline -- none of
       which sends an environment name -- would start being refused.

    2. Existing audit rows are attributed to Production too. They describe actions
       against applications that are now in Production, and leaving them NULL would
       say those actions were platform-wide, which is a different claim.
*/

CREATE TABLE "environment" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_environment" (
	"user_id" uuid NOT NULL,
	"environment_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_environment_pkey" PRIMARY KEY("user_id","environment_id")
);
--> statement-breakpoint

/*
  The estate everything already here belongs to.

  Created unconditionally: this migration runs once, and on an empty database it
  gives a new deployment somewhere for its first upload to land without an
  administrator having to create one first.
*/
INSERT INTO "environment" ("name", "description")
VALUES ('Production', 'The estate that existed before environments were introduced.');
--> statement-breakpoint

DROP INDEX "application_name_lower_uniq";--> statement-breakpoint
DROP INDEX "application_alias_name_lower_uniq";--> statement-breakpoint
DROP INDEX "application_group_name_lower_uniq";--> statement-breakpoint
DROP INDEX "package_query_input_hash_uniq";--> statement-breakpoint
DROP INDEX "report_run_monthly_period_key";--> statement-breakpoint

ALTER TABLE "application" ADD COLUMN "environment_id" uuid;--> statement-breakpoint
ALTER TABLE "application_alias" ADD COLUMN "environment_id" uuid;--> statement-breakpoint
ALTER TABLE "application_group" ADD COLUMN "environment_id" uuid;--> statement-breakpoint
ALTER TABLE "audit_log" ADD COLUMN "environment_id" uuid;--> statement-breakpoint
ALTER TABLE "ingest_token" ADD COLUMN "environment_id" uuid;--> statement-breakpoint
ALTER TABLE "package_query" ADD COLUMN "environment_id" uuid;--> statement-breakpoint
ALTER TABLE "report_run" ADD COLUMN "environment_id" uuid;--> statement-breakpoint
ALTER TABLE "vulnerability_suppression" ADD COLUMN "environment_id" uuid;--> statement-breakpoint

UPDATE "application" SET "environment_id" = (SELECT "id" FROM "environment" WHERE lower("name") = 'production');--> statement-breakpoint
UPDATE "application_alias" SET "environment_id" = (SELECT "id" FROM "environment" WHERE lower("name") = 'production');--> statement-breakpoint
UPDATE "application_group" SET "environment_id" = (SELECT "id" FROM "environment" WHERE lower("name") = 'production');--> statement-breakpoint
UPDATE "audit_log" SET "environment_id" = (SELECT "id" FROM "environment" WHERE lower("name") = 'production');--> statement-breakpoint
UPDATE "ingest_token" SET "environment_id" = (SELECT "id" FROM "environment" WHERE lower("name") = 'production');--> statement-breakpoint
UPDATE "package_query" SET "environment_id" = (SELECT "id" FROM "environment" WHERE lower("name") = 'production');--> statement-breakpoint
UPDATE "report_run" SET "environment_id" = (SELECT "id" FROM "environment" WHERE lower("name") = 'production');--> statement-breakpoint
UPDATE "vulnerability_suppression" SET "environment_id" = (SELECT "id" FROM "environment" WHERE lower("name") = 'production');--> statement-breakpoint

ALTER TABLE "application" ALTER COLUMN "environment_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "application_alias" ALTER COLUMN "environment_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "application_group" ALTER COLUMN "environment_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "package_query" ALTER COLUMN "environment_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "report_run" ALTER COLUMN "environment_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "vulnerability_suppression" ALTER COLUMN "environment_id" SET NOT NULL;--> statement-breakpoint

ALTER TABLE "user_environment" ADD CONSTRAINT "user_environment_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_environment" ADD CONSTRAINT "user_environment_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "environment_name_lower_uniq" ON "environment" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "user_environment_env_idx" ON "user_environment" USING btree ("environment_id");--> statement-breakpoint
ALTER TABLE "application" ADD CONSTRAINT "application_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_alias" ADD CONSTRAINT "application_alias_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_group" ADD CONSTRAINT "application_group_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingest_token" ADD CONSTRAINT "ingest_token_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "package_query" ADD CONSTRAINT "package_query_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_run" ADD CONSTRAINT "report_run_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_suppression" ADD CONSTRAINT "vulnerability_suppression_environment_id_environment_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "application_environment_idx" ON "application" USING btree ("environment_id");--> statement-breakpoint
CREATE INDEX "application_group_environment_idx" ON "application_group" USING btree ("environment_id");--> statement-breakpoint
CREATE INDEX "vulnerability_suppression_env_idx" ON "vulnerability_suppression" USING btree ("environment_id");--> statement-breakpoint
CREATE UNIQUE INDEX "application_name_lower_uniq" ON "application" USING btree ("environment_id",lower("name"));--> statement-breakpoint
CREATE UNIQUE INDEX "application_alias_name_lower_uniq" ON "application_alias" USING btree ("environment_id",lower("alias_name"));--> statement-breakpoint
CREATE UNIQUE INDEX "application_group_name_lower_uniq" ON "application_group" USING btree ("environment_id",lower("name"));--> statement-breakpoint
CREATE UNIQUE INDEX "package_query_input_hash_uniq" ON "package_query" USING btree ("environment_id","input_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "report_run_monthly_period_key" ON "report_run" USING btree ("environment_id","kind","period_start") WHERE kind = 'monthly';
