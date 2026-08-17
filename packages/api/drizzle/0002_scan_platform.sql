ALTER TABLE "scan" ADD COLUMN "os_name" text;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "os_version" text;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "os_pretty" text;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "runtimes" jsonb;--> statement-breakpoint
CREATE INDEX "scan_os_idx" ON "scan" USING btree ("os_name","os_version");--> statement-breakpoint
CREATE INDEX "scan_runtimes_gin" ON "scan" USING gin ("runtimes");