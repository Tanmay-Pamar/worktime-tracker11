import { pgTable, serial, text, integer, doublePrecision, boolean, timestamp, index } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: serial().primaryKey(),
  username: text().notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Login sessions. Only a SHA-256 hash of the session token is stored.
export const sessions = pgTable(
  "sessions",
  {
    tokenHash: text("token_hash").primaryKey(),
    userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (t) => [index("sessions_user_id_idx").on(t.userId)],
);

export const jobs = pgTable(
  "jobs",
  {
    id: serial().primaryKey(),
    userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    name: text().notNull(),
    hourlyRate: doublePrecision("hourly_rate").notNull(),
    color: text().notNull().default("#5267d8"),
    active: boolean().notNull().default(true),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (t) => [index("jobs_user_id_idx").on(t.userId)],
);

// start_time / end_time are stored as local wall-clock strings ("YYYY-MM-DDTHH:MM"),
// matching what the person sees on their own device.
export const shifts = pgTable("shifts", {
  id: serial().primaryKey(),
  jobId: integer("job_id").notNull().references(() => jobs.id, { onDelete: "cascade" }),
  startTime: text("start_time").notNull(),
  endTime: text("end_time"),
  breakMinutes: integer("break_minutes").notNull().default(0),
  notes: text().notNull().default(""),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
