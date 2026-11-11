CREATE TABLE "jobs" (
	"id" serial PRIMARY KEY,
	"name" text NOT NULL,
	"hourly_rate" double precision NOT NULL,
	"color" text DEFAULT '#5267d8' NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "shifts" (
	"id" serial PRIMARY KEY,
	"job_id" integer NOT NULL,
	"start_time" text NOT NULL,
	"end_time" text,
	"break_minutes" integer DEFAULT 0 NOT NULL,
	"notes" text DEFAULT '' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "shifts" ADD CONSTRAINT "shifts_job_id_jobs_id_fkey" FOREIGN KEY ("job_id") REFERENCES "jobs"("id") ON DELETE CASCADE;