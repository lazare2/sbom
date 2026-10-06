ALTER TABLE "user" ADD COLUMN "auth_subject" text;--> statement-breakpoint
-- One directory identity belongs to exactly one account.
--
-- Partial, because auth_subject is null for every local account and for every directory
-- account nobody has signed into yet. Both are legitimate and common, and a plain unique
-- index would treat them as duplicates of each other and allow only one such row.
--
-- Enforced here rather than in the sign-in path because two rows claiming one identity make
-- the match ambiguous, and the code that would have to notice is the code that is already
-- choosing between them.
CREATE UNIQUE INDEX "user_auth_subject_uniq"
  ON "user" USING btree ("auth_provider","auth_subject")
  WHERE "auth_subject" IS NOT NULL;
