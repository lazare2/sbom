CREATE TABLE "fix_candidate_check" (
	"purl" text PRIMARY KEY NOT NULL,
	"provider" text NOT NULL,
	"watermark" timestamp with time zone NOT NULL,
	"findings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"checked_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "squad" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"email" text,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "squad_application" (
	"squad_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "squad_application_pkey" PRIMARY KEY("squad_id","application_id")
);
--> statement-breakpoint
CREATE TABLE "squad_group" (
	"squad_id" uuid NOT NULL,
	"group_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "squad_group_pkey" PRIMARY KEY("squad_id","group_id")
);
--> statement-breakpoint
CREATE TABLE "squad_member" (
	"squad_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "squad_member_pkey" PRIMARY KEY("squad_id","user_id")
);
--> statement-breakpoint
ALTER TABLE "user" ADD COLUMN "first_name" text;--> statement-breakpoint
ALTER TABLE "user" ADD COLUMN "last_name" text;--> statement-breakpoint
ALTER TABLE "squad_application" ADD CONSTRAINT "squad_application_squad_id_squad_id_fk" FOREIGN KEY ("squad_id") REFERENCES "public"."squad"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "squad_application" ADD CONSTRAINT "squad_application_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "squad_group" ADD CONSTRAINT "squad_group_squad_id_squad_id_fk" FOREIGN KEY ("squad_id") REFERENCES "public"."squad"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "squad_group" ADD CONSTRAINT "squad_group_group_id_application_group_id_fk" FOREIGN KEY ("group_id") REFERENCES "public"."application_group"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "squad_member" ADD CONSTRAINT "squad_member_squad_id_squad_id_fk" FOREIGN KEY ("squad_id") REFERENCES "public"."squad"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "squad_member" ADD CONSTRAINT "squad_member_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "squad_name_lower_uniq" ON "squad" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "squad_application_application_idx" ON "squad_application" USING btree ("application_id");--> statement-breakpoint
CREATE INDEX "squad_group_group_idx" ON "squad_group" USING btree ("group_id");--> statement-breakpoint
CREATE INDEX "squad_member_user_idx" ON "squad_member" USING btree ("user_id");