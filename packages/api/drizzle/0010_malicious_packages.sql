CREATE TABLE "component_malicious" (
	"component_id" bigint NOT NULL,
	"malicious_package_id" text NOT NULL,
	"match_mode" text NOT NULL,
	"matched_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "component_malicious_pkey" PRIMARY KEY("component_id","malicious_package_id")
);
--> statement-breakpoint
CREATE TABLE "malicious_acknowledgement" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"malicious_package_id" text NOT NULL,
	"application_id" uuid,
	"state" text NOT NULL,
	"note" text NOT NULL,
	"acknowledged_by_user_id" uuid,
	"acknowledged_by_email" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "malicious_alert_sent" (
	"malicious_package_id" text NOT NULL,
	"application_id" uuid NOT NULL,
	"sent_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "malicious_alert_sent_pkey" PRIMARY KEY("malicious_package_id","application_id")
);
--> statement-breakpoint
CREATE TABLE "malicious_feed_update" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone,
	"trigger" text NOT NULL,
	"outcome" text,
	"message" text,
	"source_url" text,
	"feed_built_at" timestamp with time zone,
	"reports_total" integer,
	"reports_changed" integer,
	"reports_withdrawn" integer,
	"actor_user_id" uuid,
	"actor_email" text
);
--> statement-breakpoint
CREATE TABLE "malicious_package" (
	"id" text PRIMARY KEY NOT NULL,
	"ecosystem" text NOT NULL,
	"package_name" text NOT NULL,
	"normalized_name" text NOT NULL,
	"summary" text,
	"details" text,
	"match_mode" text NOT NULL,
	"affected_versions" text[] DEFAULT '{}' NOT NULL,
	"version_ranges" jsonb,
	"aliases" text[] DEFAULT '{}' NOT NULL,
	"sources" text[] DEFAULT '{}' NOT NULL,
	"reference_url" text,
	"published_at" timestamp with time zone,
	"modified_at" timestamp with time zone,
	"withdrawn_at" timestamp with time zone,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "component" ADD COLUMN "mal_scanned_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "component" ADD COLUMN "mal_feed_built_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "component_malicious" ADD CONSTRAINT "component_malicious_component_id_component_id_fk" FOREIGN KEY ("component_id") REFERENCES "public"."component"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "component_malicious" ADD CONSTRAINT "component_malicious_malicious_package_id_malicious_package_id_fk" FOREIGN KEY ("malicious_package_id") REFERENCES "public"."malicious_package"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "malicious_acknowledgement" ADD CONSTRAINT "malicious_acknowledgement_malicious_package_id_malicious_package_id_fk" FOREIGN KEY ("malicious_package_id") REFERENCES "public"."malicious_package"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "malicious_acknowledgement" ADD CONSTRAINT "malicious_acknowledgement_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "malicious_acknowledgement" ADD CONSTRAINT "malicious_acknowledgement_acknowledged_by_user_id_user_id_fk" FOREIGN KEY ("acknowledged_by_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "malicious_alert_sent" ADD CONSTRAINT "malicious_alert_sent_malicious_package_id_malicious_package_id_fk" FOREIGN KEY ("malicious_package_id") REFERENCES "public"."malicious_package"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "malicious_alert_sent" ADD CONSTRAINT "malicious_alert_sent_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "malicious_feed_update" ADD CONSTRAINT "malicious_feed_update_actor_user_id_user_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "component_malicious_package_idx" ON "component_malicious" USING btree ("malicious_package_id");--> statement-breakpoint
CREATE UNIQUE INDEX "malicious_ack_app_uniq" ON "malicious_acknowledgement" USING btree ("malicious_package_id","application_id") WHERE application_id IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "malicious_ack_global_uniq" ON "malicious_acknowledgement" USING btree ("malicious_package_id") WHERE application_id IS NULL;--> statement-breakpoint
CREATE INDEX "malicious_ack_application_idx" ON "malicious_acknowledgement" USING btree ("application_id");--> statement-breakpoint
CREATE INDEX "malicious_feed_update_started_idx" ON "malicious_feed_update" USING btree ("started_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "malicious_package_match_idx" ON "malicious_package" USING btree ("ecosystem","normalized_name");--> statement-breakpoint
CREATE INDEX "malicious_package_live_idx" ON "malicious_package" USING btree ("ecosystem","normalized_name") WHERE withdrawn_at IS NULL;--> statement-breakpoint
CREATE INDEX "malicious_package_published_idx" ON "malicious_package" USING btree ("published_at" DESC NULLS LAST);