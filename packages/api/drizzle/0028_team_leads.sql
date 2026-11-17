CREATE TABLE "project_visit" (
	"user_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"visited_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_visit_pkey" PRIMARY KEY("user_id","application_id")
);
--> statement-breakpoint
ALTER TABLE "squad_member" ADD COLUMN "is_lead" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "project_visit" ADD CONSTRAINT "project_visit_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_visit" ADD CONSTRAINT "project_visit_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;