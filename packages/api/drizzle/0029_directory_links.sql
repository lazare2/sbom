CREATE TABLE "squad_directory_link" (
	"squad_id" uuid PRIMARY KEY NOT NULL,
	"group_id" text NOT NULL,
	"group_name" text NOT NULL,
	"group_dn" text NOT NULL,
	"linked_at" timestamp with time zone DEFAULT now() NOT NULL,
	"linked_by" uuid
);
--> statement-breakpoint
ALTER TABLE "user" ADD COLUMN "directory_id" text;--> statement-breakpoint
ALTER TABLE "squad_directory_link" ADD CONSTRAINT "squad_directory_link_squad_id_squad_id_fk" FOREIGN KEY ("squad_id") REFERENCES "public"."squad"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "squad_directory_link" ADD CONSTRAINT "squad_directory_link_linked_by_user_id_fk" FOREIGN KEY ("linked_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "squad_directory_link_group_uniq" ON "squad_directory_link" USING btree ("group_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_directory_id_uniq" ON "user" USING btree ("directory_id");