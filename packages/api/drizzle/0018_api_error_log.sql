CREATE TABLE "api_error" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"method" text NOT NULL,
	"path" text NOT NULL,
	"status_code" integer NOT NULL,
	"code" text NOT NULL,
	"message" text NOT NULL,
	"details" jsonb,
	"actor_user_id" uuid,
	"actor_email" text
);
--> statement-breakpoint
ALTER TABLE "api_error" ADD CONSTRAINT "api_error_actor_user_id_user_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "api_error_occurred_idx" ON "api_error" USING btree ("occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "api_error_code_idx" ON "api_error" USING btree ("code");--> statement-breakpoint
CREATE INDEX "api_error_status_idx" ON "api_error" USING btree ("status_code");