-- Password recovery moves from emailed links to admin-issued credentials.
--
-- `user_token` held single-use hashes for password-reset and account-setup
-- links. User emails are login identifiers rather than mailboxes, so those
-- links had no delivery channel and the table only ever accumulated rows that
-- could never be redeemed. Dropping it discards nothing an operator can use:
-- recovery is now an admin issuing a password directly.
DROP TABLE "user_token" CASCADE;--> statement-breakpoint
ALTER TABLE "user" ADD COLUMN "must_change_password" boolean DEFAULT false NOT NULL;
