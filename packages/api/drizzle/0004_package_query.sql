CREATE TABLE "package_query" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"input_hash" text NOT NULL,
	"raw_input" text NOT NULL,
	"entry_count" integer DEFAULT 0 NOT NULL,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_accessed_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "package_query" ADD CONSTRAINT "package_query_created_by_user_id_user_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "package_query_input_hash_uniq" ON "package_query" USING btree ("input_hash");--> statement-breakpoint
CREATE INDEX "package_query_last_accessed_idx" ON "package_query" USING btree ("last_accessed_at");