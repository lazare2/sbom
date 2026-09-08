CREATE TABLE "user_application" (
	"user_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_application_pkey" PRIMARY KEY("user_id","application_id")
);
--> statement-breakpoint
CREATE TABLE "user_group" (
	"user_id" uuid NOT NULL,
	"group_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_group_pkey" PRIMARY KEY("user_id","group_id")
);
--> statement-breakpoint
ALTER TABLE "user" ADD COLUMN "application_access_restricted" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "user_application" ADD CONSTRAINT "user_application_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_application" ADD CONSTRAINT "user_application_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_group" ADD CONSTRAINT "user_group_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_group" ADD CONSTRAINT "user_group_group_id_application_group_id_fk" FOREIGN KEY ("group_id") REFERENCES "public"."application_group"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "user_application_application_idx" ON "user_application" USING btree ("application_id");--> statement-breakpoint
CREATE INDEX "user_group_group_idx" ON "user_group" USING btree ("group_id");