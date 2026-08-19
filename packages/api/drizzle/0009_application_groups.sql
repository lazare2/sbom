CREATE TABLE "application_group" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "application_group_member" (
	"group_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "application_group_member_pkey" PRIMARY KEY("group_id","application_id")
);
--> statement-breakpoint
ALTER TABLE "application_group_member" ADD CONSTRAINT "application_group_member_group_id_application_group_id_fk" FOREIGN KEY ("group_id") REFERENCES "public"."application_group"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_group_member" ADD CONSTRAINT "application_group_member_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "application_group_name_lower_uniq" ON "application_group" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "application_group_member_application_idx" ON "application_group_member" USING btree ("application_id");