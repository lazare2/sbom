CREATE TABLE "squad_tribe" (
	"squad_id" uuid NOT NULL,
	"tribe_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "squad_tribe_pkey" PRIMARY KEY("squad_id","tribe_id")
);
--> statement-breakpoint
CREATE TABLE "tribe" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"email" text,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tribe_application" (
	"tribe_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tribe_application_pkey" PRIMARY KEY("tribe_id","application_id")
);
--> statement-breakpoint
ALTER TABLE "attribute_definition" ADD COLUMN "is_required" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "attribute_definition" ADD COLUMN "linked_to" text;--> statement-breakpoint
ALTER TABLE "scan_vuln_summary" ADD COLUMN "superseded_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "scan_vuln_summary" ADD COLUMN "superseded_counts" jsonb;--> statement-breakpoint
ALTER TABLE "squad_tribe" ADD CONSTRAINT "squad_tribe_squad_id_squad_id_fk" FOREIGN KEY ("squad_id") REFERENCES "public"."squad"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "squad_tribe" ADD CONSTRAINT "squad_tribe_tribe_id_tribe_id_fk" FOREIGN KEY ("tribe_id") REFERENCES "public"."tribe"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tribe_application" ADD CONSTRAINT "tribe_application_tribe_id_tribe_id_fk" FOREIGN KEY ("tribe_id") REFERENCES "public"."tribe"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tribe_application" ADD CONSTRAINT "tribe_application_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "squad_tribe_tribe_idx" ON "squad_tribe" USING btree ("tribe_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tribe_name_lower_uniq" ON "tribe" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "tribe_application_application_idx" ON "tribe_application" USING btree ("application_id");--> statement-breakpoint
CREATE UNIQUE INDEX "attribute_definition_linked_uniq" ON "attribute_definition" USING btree ("linked_to");--> statement-breakpoint
/*
  The squad and tribe attributes now mirror access. Link the existing definitions (or create
  them), turn every value already typed into an application's attribute into a real squad or
  tribe assignment, and rewrite the attribute from those assignments.

  A value that names no squad yet becomes a squad with no members. That grants nobody anything,
  and it keeps the label an administrator typed instead of dropping it; members and a tribe are
  added afterwards. Values are split on commas so "payments, storefront" becomes two squads, and
  names differing only in case become one squad spelled the way most applications spelled it.
*/
UPDATE "attribute_definition"
   SET "linked_to" = 'squad', "type" = 'string', "options" = NULL
 WHERE "key" = 'squad';--> statement-breakpoint
INSERT INTO "attribute_definition" ("key", "label", "type", "sort_order", "linked_to")
SELECT 'squad', 'Squad', 'string', 10, 'squad'
 WHERE NOT EXISTS (SELECT 1 FROM "attribute_definition" WHERE "key" = 'squad');--> statement-breakpoint
UPDATE "attribute_definition"
   SET "linked_to" = 'tribe', "type" = 'string', "options" = NULL
 WHERE "key" = 'tribe';--> statement-breakpoint
INSERT INTO "attribute_definition" ("key", "label", "type", "sort_order", "linked_to")
SELECT 'tribe', 'Tribe', 'string', 5, 'tribe'
 WHERE NOT EXISTS (SELECT 1 FROM "attribute_definition" WHERE "key" = 'tribe');--> statement-breakpoint
CREATE TEMPORARY TABLE "legacy_linked_value" AS
SELECT DISTINCT a."id" AS "application_id", k."kind", btrim(v."name") AS "name"
  FROM "application" a
 CROSS JOIN (VALUES ('squad'), ('tribe')) AS k("kind")
 CROSS JOIN LATERAL regexp_split_to_table(a."attributes" ->> k."kind", ',') AS v("name")
 WHERE jsonb_typeof(a."attributes" -> k."kind") = 'string'
   AND btrim(v."name") <> '';--> statement-breakpoint
INSERT INTO "squad" ("name")
SELECT mode() WITHIN GROUP (ORDER BY "name") FROM "legacy_linked_value" WHERE "kind" = 'squad'
 GROUP BY lower("name")
ON CONFLICT (lower("name")) DO NOTHING;--> statement-breakpoint
INSERT INTO "tribe" ("name")
SELECT mode() WITHIN GROUP (ORDER BY "name") FROM "legacy_linked_value" WHERE "kind" = 'tribe'
 GROUP BY lower("name")
ON CONFLICT (lower("name")) DO NOTHING;--> statement-breakpoint
INSERT INTO "squad_application" ("squad_id", "application_id")
SELECT s."id", l."application_id"
  FROM "legacy_linked_value" l
  JOIN "squad" s ON lower(s."name") = lower(l."name")
 WHERE l."kind" = 'squad'
ON CONFLICT DO NOTHING;--> statement-breakpoint
INSERT INTO "tribe_application" ("tribe_id", "application_id")
SELECT t."id", l."application_id"
  FROM "legacy_linked_value" l
  JOIN "tribe" t ON lower(t."name") = lower(l."name")
 WHERE l."kind" = 'tribe'
ON CONFLICT DO NOTHING;--> statement-breakpoint
UPDATE "application" a
   SET "attributes" = (a."attributes" - 'squad' - 'tribe')
     || COALESCE((
          SELECT jsonb_build_object('squad', string_agg(s."name", ', ' ORDER BY lower(s."name")))
            FROM "squad_application" sa JOIN "squad" s ON s."id" = sa."squad_id"
           WHERE sa."application_id" = a."id"
          HAVING count(*) > 0), '{}'::jsonb)
     || COALESCE((
          SELECT jsonb_build_object('tribe', string_agg(t."name", ', ' ORDER BY lower(t."name")))
            FROM "tribe_application" ta JOIN "tribe" t ON t."id" = ta."tribe_id"
           WHERE ta."application_id" = a."id"
          HAVING count(*) > 0), '{}'::jsonb)
 WHERE a."attributes" ?| ARRAY['squad', 'tribe']
    OR EXISTS (SELECT 1 FROM "squad_application" sa WHERE sa."application_id" = a."id")
    OR EXISTS (SELECT 1 FROM "tribe_application" ta WHERE ta."application_id" = a."id");--> statement-breakpoint
DROP TABLE "legacy_linked_value";
