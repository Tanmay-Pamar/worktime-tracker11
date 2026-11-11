CREATE TABLE "sessions" (
	"token_hash" text PRIMARY KEY,
	"user_id" integer NOT NULL,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY,
	"username" text NOT NULL UNIQUE,
	"password_hash" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
INSERT INTO "users" ("username", "password_hash") VALUES ('admin', 'scrypt$7f5aed7f7b92f8c35c3f5b8b6608eed5$7c9493448c07e55fd85074b0d0142904b9e802765233d42906827e3d07cfe4887b24ba9bc5ae1554e65cbc52ccc1e2f46bfb520ec6a7f65720d52ec17584581c') ON CONFLICT ("username") DO NOTHING;--> statement-breakpoint
ALTER TABLE "jobs" ADD COLUMN "user_id" integer;--> statement-breakpoint
UPDATE "jobs" SET "user_id" = (SELECT "id" FROM "users" WHERE "username" = 'admin') WHERE "user_id" IS NULL;--> statement-breakpoint
ALTER TABLE "jobs" ALTER COLUMN "user_id" SET NOT NULL;--> statement-breakpoint
CREATE INDEX "jobs_user_id_idx" ON "jobs" ("user_id");--> statement-breakpoint
CREATE INDEX "sessions_user_id_idx" ON "sessions" ("user_id");--> statement-breakpoint
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;