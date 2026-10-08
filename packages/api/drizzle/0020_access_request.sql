CREATE TABLE "access_request" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider" text NOT NULL,
	"subject" text NOT NULL,
	"email" text,
	"display_name" text,
	"reason" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 1 NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"resolved_at" timestamp with time zone,
	"resolved_by_user_id" uuid,
	"created_user_id" uuid
);
--> statement-breakpoint
ALTER TABLE "access_request" ADD CONSTRAINT "access_request_resolved_by_user_id_user_id_fk" FOREIGN KEY ("resolved_by_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_request" ADD CONSTRAINT "access_request_created_user_id_user_id_fk" FOREIGN KEY ("created_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "access_request_status_idx" ON "access_request" USING btree ("status","last_seen_at");
--> statement-breakpoint
/*
  One pending request per directory identity.

  Hand-written: drizzle-kit cannot infer a partial index from the schema, and this one is not an
  optimisation. It is where "somebody refused three times is one person waiting, not three rows"
  is actually enforced -- the recording path upserts onto this index, so without it every repeat
  attempt would insert again and the queue would stop being a count of colleagues.

  Scoped to pending on purpose. Unique across every row would make a dismissal permanent: the
  same person trying again next month would collide with the dismissed row and silently
  disappear, which is the opposite of what this queue exists for. Scoped this way, a repeat folds
  into the open row, an attempt after a dismissal opens a fresh one, and resolved rows pile up as
  history without ever blocking anybody.
*/
CREATE UNIQUE INDEX "access_request_pending_identity_uniq"
  ON "access_request" USING btree ("provider","subject") WHERE status = 'pending';
