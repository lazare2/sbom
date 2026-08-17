-- Required by "component_name_trgm_idx" below, which backs partial package-name
-- search. Added by hand on top of the drizzle-kit output: drizzle has no way to
-- express an extension, and CREATE EXTENSION must precede the index that uses
-- its operator class. Idempotent, and never dropped by a later `generate`.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
--> statement-breakpoint
-- gen_random_uuid() is built into Postgres 13+. Kept explicit so the schema also
-- applies cleanly against an older server.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
--> statement-breakpoint
CREATE TABLE "application" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"attributes" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"latest_scan_id" uuid,
	"last_scan_at" timestamp with time zone,
	"scan_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "application_alias" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"alias_name" text NOT NULL,
	"application_id" uuid NOT NULL,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "attribute_definition" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"type" text DEFAULT 'string' NOT NULL,
	"options" jsonb,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"actor_user_id" uuid,
	"actor_email" text,
	"action" text NOT NULL,
	"target_type" text NOT NULL,
	"target_id" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "component" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"identity_hash" text NOT NULL,
	"name" text NOT NULL,
	"version" text,
	"ecosystem" text DEFAULT 'unknown' NOT NULL,
	"purl" text,
	"cpe" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ingest_token" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"token_hash" text NOT NULL,
	"token_suffix" text NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_by_user_id" uuid,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"application_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"commit_sha" text,
	"build_number" text,
	"pipeline_id" text,
	"image_ref" text,
	"branch" text,
	"ingest_token_name" text,
	"sbom_blob_key" text NOT NULL,
	"sbom_size_bytes" bigint DEFAULT 0 NOT NULL,
	"sbom_sha256" text NOT NULL,
	"spec_version" text,
	"serial_number" text,
	"tool_name" text,
	"tool_version" text,
	"component_count" integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_component" (
	"scan_id" uuid NOT NULL,
	"component_id" bigint NOT NULL,
	"application_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scan_component_pkey" PRIMARY KEY("scan_id","component_id")
);
--> statement-breakpoint
CREATE TABLE "session" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip_address" text,
	"user_agent" text
);
--> statement-breakpoint
CREATE TABLE "user" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"password_hash" text,
	"role" text DEFAULT 'user' NOT NULL,
	"auth_provider" text DEFAULT 'local' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_token" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"purpose" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "application" ADD CONSTRAINT "application_latest_scan_id_scan_id_fk" FOREIGN KEY ("latest_scan_id") REFERENCES "public"."scan"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_alias" ADD CONSTRAINT "application_alias_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_alias" ADD CONSTRAINT "application_alias_created_by_user_id_user_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_actor_user_id_user_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingest_token" ADD CONSTRAINT "ingest_token_created_by_user_id_user_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan" ADD CONSTRAINT "scan_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_component" ADD CONSTRAINT "scan_component_scan_id_scan_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scan"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_component" ADD CONSTRAINT "scan_component_component_id_component_id_fk" FOREIGN KEY ("component_id") REFERENCES "public"."component"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_component" ADD CONSTRAINT "scan_component_application_id_application_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_token" ADD CONSTRAINT "user_token_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "application_name_lower_uniq" ON "application" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "application_status_idx" ON "application" USING btree ("status");--> statement-breakpoint
CREATE INDEX "application_last_scan_at_idx" ON "application" USING btree ("last_scan_at");--> statement-breakpoint
CREATE INDEX "application_attributes_gin" ON "application" USING gin ("attributes");--> statement-breakpoint
CREATE UNIQUE INDEX "application_alias_name_lower_uniq" ON "application_alias" USING btree (lower("alias_name"));--> statement-breakpoint
CREATE INDEX "application_alias_app_idx" ON "application_alias" USING btree ("application_id");--> statement-breakpoint
CREATE UNIQUE INDEX "attribute_definition_key_uniq" ON "attribute_definition" USING btree ("key");--> statement-breakpoint
CREATE INDEX "attribute_definition_sort_idx" ON "attribute_definition" USING btree ("sort_order");--> statement-breakpoint
CREATE INDEX "audit_log_created_idx" ON "audit_log" USING btree ("created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_log_target_idx" ON "audit_log" USING btree ("target_type","target_id");--> statement-breakpoint
CREATE INDEX "audit_log_actor_idx" ON "audit_log" USING btree ("actor_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "component_identity_hash_uniq" ON "component" USING btree ("identity_hash");--> statement-breakpoint
CREATE INDEX "component_name_trgm_idx" ON "component" USING gin ("name" gin_trgm_ops);--> statement-breakpoint
CREATE INDEX "component_name_lower_idx" ON "component" USING btree (lower("name"),"version");--> statement-breakpoint
CREATE INDEX "component_ecosystem_idx" ON "component" USING btree ("ecosystem");--> statement-breakpoint
CREATE INDEX "component_purl_idx" ON "component" USING btree ("purl");--> statement-breakpoint
CREATE UNIQUE INDEX "ingest_token_name_uniq" ON "ingest_token" USING btree ("name");--> statement-breakpoint
CREATE UNIQUE INDEX "ingest_token_hash_uniq" ON "ingest_token" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "ingest_token_active_idx" ON "ingest_token" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "scan_application_created_idx" ON "scan" USING btree ("application_id","created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "scan_created_idx" ON "scan" USING btree ("created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "scan_commit_sha_idx" ON "scan" USING btree ("commit_sha");--> statement-breakpoint
CREATE INDEX "scan_component_search_idx" ON "scan_component" USING btree ("component_id","application_id","scan_id");--> statement-breakpoint
CREATE INDEX "scan_component_application_idx" ON "scan_component" USING btree ("application_id");--> statement-breakpoint
CREATE INDEX "session_user_idx" ON "session" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "session_expires_idx" ON "session" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "user_email_lower_uniq" ON "user" USING btree (lower("email"));--> statement-breakpoint
CREATE INDEX "user_role_idx" ON "user" USING btree ("role");--> statement-breakpoint
CREATE INDEX "user_token_user_purpose_idx" ON "user_token" USING btree ("user_id","purpose");--> statement-breakpoint
CREATE INDEX "user_token_expires_idx" ON "user_token" USING btree ("expires_at");