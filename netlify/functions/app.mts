import type { Config } from "@netlify/functions";
import { and, asc, desc, eq, gte, isNull, lte, ne, sql } from "drizzle-orm";
import { db } from "../../db/index.js";
import { jobs, sessions, shifts, users } from "../../db/schema.js";
import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";

// ---------- helpers ----------

type Job = typeof jobs.$inferSelect;
type ShiftRow = {
  id: number;
  jobId: number;
  startTime: string;
  endTime: string | null;
  breakMinutes: number;
  notes: string;
  jobName: string;
  hourlyRate: number;
  color: string;
};

const esc = (v: unknown) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const money = (n: number) => n.toFixed(2);
const round2 = (n: number) => Math.round(n * 100) / 100;
const pad = (n: number) => String(n).padStart(2, "0");

const LOCAL_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

/** Parse a local "YYYY-MM-DDTHH:MM" string to a comparable epoch (treating it as UTC). */
const toEpoch = (s: string) => Date.parse(s.slice(0, 16) + ":00Z");

/** Format a Date whose UTC fields hold local wall-clock values. */
const fmtLocal = (d: Date) =>
  `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;

function getCookies(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

/** The person's local "now" as a Date with local wall-clock values in UTC fields. */
function localNow(req: Request, clientNow?: string | null): Date {
  if (clientNow && LOCAL_RE.test(clientNow)) return new Date(toEpoch(clientNow));
  const offset = parseInt(getCookies(req).tzo || "0", 10) || 0; // minutes, as from getTimezoneOffset()
  return new Date(Date.now() - offset * 60_000);
}

function shiftHours(s: { startTime: string; endTime: string | null; breakMinutes: number }) {
  if (!s.endTime) return 0;
  const seconds = Math.max(0, (toEpoch(s.endTime) - toEpoch(s.startTime)) / 1000 - (s.breakMinutes || 0) * 60);
  return round2(seconds / 3600);
}
const shiftPay = (s: ShiftRow) => round2(shiftHours(s) * s.hourlyRate);

const shiftSelect = {
  id: shifts.id,
  jobId: shifts.jobId,
  startTime: shifts.startTime,
  endTime: shifts.endTime,
  breakMinutes: shifts.breakMinutes,
  notes: shifts.notes,
  jobName: jobs.name,
  hourlyRate: jobs.hourlyRate,
  color: jobs.color,
};

function redirect(location: string, flash?: [string, string]) {
  const headers = new Headers({ Location: location });
  if (flash) headers.append("Set-Cookie", `flash=${encodeURIComponent(JSON.stringify(flash))}; Path=/; HttpOnly; SameSite=Lax`);
  return new Response(null, { status: 303, headers });
}

async function formData(req: Request) {
  const f = await req.formData();
  return (k: string) => {
    const v = f.get(k);
    return typeof v === "string" ? v : "";
  };
}

// ---------- auth ----------

type User = { id: number; username: string; createdAt: Date; tokenHash: string };

const SESSION_COOKIE = "wt_session";
const SESSION_DAYS = 30;
const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;

const scryptAsync = (pw: string, salt: Buffer) =>
  new Promise<Buffer>((resolve, reject) => scrypt(pw, salt, 64, (err, key) => (err ? reject(err) : resolve(key))));

async function hashPassword(pw: string) {
  const salt = randomBytes(16);
  const key = await scryptAsync(pw, salt);
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}

async function verifyPassword(pw: string, stored: string) {
  const [alg, saltHex, keyHex] = stored.split("$");
  if (alg !== "scrypt") {
    // Legacy plain-text value (added outside the app): compare in constant time, then caller rehashes it.
    await scryptAsync(pw, randomBytes(16));
    const a = Buffer.from(sha256(pw)), b = Buffer.from(sha256(stored));
    return stored.length > 0 && timingSafeEqual(a, b);
  }
  if (!saltHex || !keyHex) return false;
  const expected = Buffer.from(keyHex, "hex");
  const key = await scryptAsync(pw, Buffer.from(saltHex, "hex"));
  return key.length === expected.length && timingSafeEqual(key, expected);
}

const sha256 = (v: string) => createHash("sha256").update(v).digest("hex");
const isSecure = (req: Request) => new URL(req.url).protocol === "https:";

async function currentUser(req: Request): Promise<User | null> {
  const token = getCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  const [row] = await db
    .select({ id: users.id, username: users.username, createdAt: users.createdAt, expiresAt: sessions.expiresAt })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(eq(sessions.tokenHash, sha256(token)))
    .limit(1);
  if (!row || row.expiresAt.getTime() < Date.now()) return null;
  return { id: row.id, username: row.username, createdAt: row.createdAt, tokenHash: sha256(token) };
}

async function startSession(req: Request, userId: number) {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86_400_000);
  await db.delete(sessions).where(and(eq(sessions.userId, userId), lte(sessions.expiresAt, new Date())));
  await db.insert(sessions).values({ tokenHash: sha256(token), userId, expiresAt });
  const res = redirect("/");
  res.headers.append(
    "Set-Cookie",
    `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${isSecure(req) ? "; Secure" : ""}`,
  );
  return res;
}

function authPage(req: Request, mode: "login" | "signup", opts: { error?: string; username?: string; status?: number } = {}) {
  const cookies = getCookies(req);
  const headers = new Headers({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  let flashHtml = opts.error ? `<div class="flash error">${esc(opts.error)}</div>` : "";
  if (cookies.flash) {
    try {
      const [cat, msg] = JSON.parse(cookies.flash);
      if (!flashHtml) flashHtml = `<div class="flash ${esc(cat)}">${esc(msg)}</div>`;
    } catch {}
    headers.append("Set-Cookie", "flash=; Path=/; Max-Age=0; SameSite=Lax");
  }
  const login = mode === "login";
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${login ? "Log in" : "Sign up"} | WorkTime</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body class="auth-body">
<main class="auth-wrap">
  <div class="auth-brand"><span class="brand-mark">W</span><span>WorkTime<small>PERSONAL TRACKER</small></span></div>
  <article class="panel auth-card">
    <h2>${login ? "Welcome back" : "Create your account"}</h2>
    <p class="muted-text">${login ? "Log in to see your jobs, shifts and earnings." : "Sign up to start tracking your own work hours. Your data is private to your account."}</p>
    ${flashHtml}
    <form method="post" action="${login ? "/login" : "/signup"}" class="form-stack">
      <label>Username<input name="username" value="${esc(opts.username ?? "")}" autocomplete="username" required ${login ? "" : 'minlength="3" maxlength="32" pattern="[A-Za-z0-9_.\\-]{3,32}" title="3–32 characters: letters, numbers, dots, dashes or underscores"'} autofocus></label>
      <label>Password<input type="password" name="password" autocomplete="${login ? "current-password" : "new-password"}" required ${login ? "" : 'minlength="8" maxlength="200"'}></label>
      ${login ? "" : `<label>Confirm password<input type="password" name="confirm" autocomplete="new-password" required minlength="8" maxlength="200"></label>`}
      <button class="button primary" type="submit">${login ? "Log in" : "Create account"}</button>
    </form>
    <p class="auth-switch">${login ? `New here? <a href="/signup">Create an account →</a>` : `Already have an account? <a href="/login">Log in →</a>`}</p>
  </article>
</main>
</body></html>`;
  return new Response(html, { status: opts.status ?? 200, headers });
}

async function loginRoute(req: Request) {
  if (req.method !== "POST") return authPage(req, "login");
  const get = await formData(req);
  const username = get("username").trim().toLowerCase();
  const password = get("password");
  // Match usernames case-insensitively so rows edited directly in the database (e.g. "Admin") still work.
  const [u] = username ? await db.select().from(users).where(sql`lower(${users.username}) = ${username}`).limit(1) : [];
  // Always run a hash so response timing doesn't reveal whether the username exists.
  const ok = u ? await verifyPassword(password, u.passwordHash) : (await hashPassword(password), false);
  if (!u || !ok) return authPage(req, "login", { error: "Incorrect username or password.", username, status: 401 });
  // Upgrade passwords that were stored without hashing (e.g. inserted by hand) to a salted scrypt hash.
  if (!u.passwordHash.startsWith("scrypt$")) {
    await db.update(users).set({ passwordHash: await hashPassword(password) }).where(eq(users.id, u.id));
  }
  return startSession(req, u.id);
}

async function signupRoute(req: Request) {
  if (req.method !== "POST") return authPage(req, "signup");
  const get = await formData(req);
  const username = get("username").trim().toLowerCase();
  const password = get("password");
  const fail = (error: string) => authPage(req, "signup", { error, username, status: 400 });
  if (!USERNAME_RE.test(username)) return fail("Username must be 3–32 characters: letters, numbers, dots, dashes or underscores.");
  if (password.length < 8 || password.length > 200) return fail("Password must be at least 8 characters.");
  if (password !== get("confirm")) return fail("The two passwords don't match.");
  const [created] = await db
    .insert(users)
    .values({ username, passwordHash: await hashPassword(password) })
    .onConflictDoNothing({ target: users.username })
    .returning({ id: users.id });
  if (!created) return fail("That username is already taken.");
  return startSession(req, created.id);
}

async function logoutRoute(req: Request) {
  const token = getCookies(req)[SESSION_COOKIE];
  if (token) await db.delete(sessions).where(eq(sessions.tokenHash, sha256(token)));
  const res = redirect("/login", ["success", "You have been logged out."]);
  res.headers.append("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${isSecure(req) ? "; Secure" : ""}`);
  return res;
}

/** Load a job only if it belongs to the user. */
async function ownJob(u: User, jobId: number) {
  if (!jobId) return null;
  const [j] = await db.select().from(jobs).where(and(eq(jobs.id, jobId), eq(jobs.userId, u.id))).limit(1);
  return j ?? null;
}

/** Load a shift only if its job belongs to the user. */
async function ownShift(u: User, shiftId: number) {
  const [row] = await db
    .select({ shift: shifts })
    .from(shifts)
    .innerJoin(jobs, eq(jobs.id, shifts.jobId))
    .where(and(eq(shifts.id, shiftId), eq(jobs.userId, u.id)))
    .limit(1);
  return row?.shift ?? null;
}

// ---------- layout ----------

type Nav = "dashboard" | "clock" | "jobs" | "timesheets" | "reports" | "profile" | "";

function page(req: Request, u: User, opts: { title: string; heading?: string; nav: Nav; body: string; scripts?: string; status?: number }) {
  const cookies = getCookies(req);
  let flashHtml = "";
  const headers = new Headers({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  if (cookies.flash) {
    try {
      const [cat, msg] = JSON.parse(cookies.flash);
      flashHtml = `<div class="flash ${esc(cat)}">${esc(msg)}</div>`;
    } catch {}
    headers.append("Set-Cookie", "flash=; Path=/; Max-Age=0; SameSite=Lax");
  }
  const a = (n: Nav) => (opts.nav === n ? "active" : "");
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(opts.title)} | WorkTime</title>
  <link rel="stylesheet" href="/static/style.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="/"><span class="brand-mark">W</span><span>WorkTime<small>PERSONAL TRACKER</small></span></a>
    <nav>
      <a href="/" class="${a("dashboard")}">▦ <span>Dashboard</span></a>
      <a href="/clock" class="${a("clock")}">◷ <span>Clock In / Out</span></a>
      <a href="/jobs" class="${a("jobs")}">▤ <span>My Jobs</span></a>
      <a href="/timesheets" class="${a("timesheets")}">▧ <span>Timesheets</span></a>
      <a href="/reports" class="${a("reports")}">▥ <span>Reports</span></a>
      <a href="/profile" class="${a("profile")}">◉ <span>Profile</span></a>
    </nav>
    <div class="sidebar-bottom"><a class="avatar" href="/profile" title="Profile">${esc(u.username.slice(0, 2).toUpperCase())}</a><div class="account-info"><strong>${esc(u.username)}</strong><small><a href="/profile">View profile</a></small></div><form method="post" action="/logout"><button class="text-button logout-button" type="submit" title="Log out">Log out</button></form></div>
  </aside>
  <main class="main">
    <header class="topbar"><div><span class="eyebrow">WORK HOURS MANAGEMENT</span><h1>${esc(opts.heading ?? opts.title)}</h1></div><a class="button primary" href="/shift/new">＋ Add shift</a></header>
    <section class="content">
      ${flashHtml}
      ${opts.body}
    </section>
    <footer>WorkTime · CAD currency · Gross earnings estimates</footer>
  </main>
</div>
<script src="/static/app.js"></script>
${opts.scripts ?? ""}
</body></html>`;
  return new Response(html, { status: opts.status ?? 200, headers });
}

const jobOptions = (list: Job[], selected?: number | string) =>
  list
    .map(
      (j) =>
        `<option value="${j.id}" ${String(selected) === String(j.id) ? "selected" : ""}>${esc(j.name)} — $${money(j.hourlyRate)}/hr</option>`,
    )
    .join("");

const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

// ---------- pages ----------

async function dashboard(req: Request, u: User) {
  const activeJobs = await db.select().from(jobs).where(and(eq(jobs.active, true), eq(jobs.userId, u.id))).orderBy(asc(jobs.name));
  const all: ShiftRow[] = await db.select(shiftSelect).from(shifts).innerJoin(jobs, eq(jobs.id, shifts.jobId)).where(eq(jobs.userId, u.id)).orderBy(desc(shifts.startTime));
  const now = localNow(req);
  const monthStart = `${now.getUTCFullYear()}-${pad(now.getUTCMonth() + 1)}-01T00:00`;
  const dow = (now.getUTCDay() + 6) % 7; // Monday = 0
  const ws = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - dow));
  const weekStart = fmtLocal(ws);
  const openShift = all.find((s) => !s.endTime);

  let monthHours = 0, weekHours = 0, monthPay = 0;
  const jobTotals = new Map<string, number>();
  const recent: (ShiftRow & { hours: number; pay: number })[] = [];
  for (const s of all) {
    const h = shiftHours(s), p = shiftPay(s);
    if (s.startTime >= monthStart && s.endTime) {
      monthHours += h;
      monthPay += p;
      jobTotals.set(s.jobName, (jobTotals.get(s.jobName) || 0) + p);
    }
    if (s.startTime >= weekStart && s.endTime) weekHours += h;
    if (recent.length < 8) recent.push({ ...s, hours: h, pay: p });
  }
  const labels = [...jobTotals.keys()];
  const values = [...jobTotals.values()].map(round2);
  const dateLabel = `${DAYS[now.getUTCDay()]}, ${MONTHS[now.getUTCMonth()]} ${pad(now.getUTCDate())}, ${now.getUTCFullYear()}`;

  const body = `
<div class="welcome-row"><div><h2>Your work at a glance</h2><p>Track shifts across all your jobs in one place.</p></div><div class="date-chip">${dateLabel}</div></div>
${openShift ? `<div class="active-banner"><div><span class="live-dot"></span><strong>Currently clocked in at ${esc(openShift.jobName)}</strong><p>Started ${esc(openShift.startTime.replace("T", " "))}</p></div><a class="button light" href="/clock">View active shift</a></div>` : ""}
<div class="stats-grid">
 <article class="stat-card"><div class="stat-label">Earnings this month</div><div class="stat-value">$${money(monthPay)}</div><div class="stat-foot">Gross pay estimate · CAD</div><div class="stat-icon green">$</div></article>
 <article class="stat-card"><div class="stat-label">Hours this month</div><div class="stat-value">${money(monthHours)} <small>hrs</small></div><div class="stat-foot">Completed shifts</div><div class="stat-icon blue">◷</div></article>
 <article class="stat-card"><div class="stat-label">Hours this week</div><div class="stat-value">${money(weekHours)} <small>hrs</small></div><div class="stat-foot">Since Monday</div><div class="stat-icon purple">▦</div></article>
 <article class="stat-card"><div class="stat-label">Active jobs</div><div class="stat-value">${activeJobs.length}</div><div class="stat-foot">Employers being tracked</div><div class="stat-icon orange">▤</div></article>
</div>
<div class="two-col">
 <article class="panel"><div class="panel-head"><div><h3>Earnings by job</h3><p>Current month · CAD</p></div><a href="/reports">View report →</a></div>
 ${labels.length ? `<div class="chart-wrap"><canvas id="earningsChart"></canvas></div>` : `<div class="empty-state"><div class="empty-icon">▥</div><strong>No earnings recorded yet</strong><p>Add jobs and completed shifts to see your breakdown.</p></div>`}</article>
 <article class="panel"><div class="panel-head"><div><h3>Quick actions</h3><p>Manage your working time</p></div></div>
  <a class="action-link" href="/clock"><span class="action-icon">◷</span><span><strong>Clock in / out</strong><small>Start or finish a shift</small></span><b>→</b></a>
  <a class="action-link" href="/jobs"><span class="action-icon">▤</span><span><strong>Add a job</strong><small>Set employer and hourly rate</small></span><b>→</b></a>
  <a class="action-link" href="/shift/new"><span class="action-icon">＋</span><span><strong>Enter past hours</strong><small>Manually record a shift</small></span><b>→</b></a>
 </article>
</div>
<article class="panel"><div class="panel-head"><div><h3>Recent shifts</h3><p>Your latest recorded work sessions</p></div><a href="/timesheets">All timesheets →</a></div>
${
  recent.length
    ? `<div class="table-scroll"><table><thead><tr><th>JOB</th><th>DATE</th><th>TIME</th><th>HOURS</th><th>GROSS PAY</th><th>STATUS</th></tr></thead><tbody>
${recent
  .map(
    (s) =>
      `<tr><td><span class="job-dot" style="background:${esc(s.color)}"></span><strong>${esc(s.jobName)}</strong></td><td>${esc(s.startTime.slice(0, 10))}</td><td>${esc(s.startTime.slice(11, 16))} – ${s.endTime ? esc(s.endTime.slice(11, 16)) : "—"}</td><td>${s.endTime ? money(s.hours) : "—"}</td><td>${s.endTime ? "$" + money(s.pay) : "—"}</td><td><span class="status ${s.endTime ? "done" : "open"}">${s.endTime ? "Completed" : "Active"}</span></td></tr>`,
  )
  .join("")}
</tbody></table></div>`
    : `<div class="empty-state compact"><strong>No shifts yet</strong><p>Your recorded shifts will appear here.</p></div>`
}
</article>`;

  const scripts = `<script>
const labels=${JSON.stringify(labels).replace(/</g, "\\u003c")}, values=${JSON.stringify(values)};
if(document.getElementById('earningsChart')) new Chart(document.getElementById('earningsChart'),{type:'doughnut',data:{labels,datasets:[{data:values,backgroundColor:['#5267d8','#16a477','#e8a23a','#8b72d9','#e27676'],borderWidth:0,hoverOffset:5}]},options:{responsive:true,maintainAspectRatio:false,cutout:'70%',plugins:{legend:{position:'bottom',labels:{usePointStyle:true,boxWidth:7,padding:18}}}}});
</script>`;
  return page(req, u, { title: "Dashboard", nav: "dashboard", body, scripts });
}

async function jobsPage(req: Request, u: User) {
  if (req.method === "POST") {
    const get = await formData(req);
    const name = get("name").trim().slice(0, 80);
    const rate = parseFloat(get("hourly_rate"));
    if (!name || !Number.isFinite(rate) || rate < 0) {
      return redirect("/jobs", ["error", "Enter a job name and a valid non-negative hourly rate."]);
    }
    const color = /^#[0-9a-fA-F]{6}$/.test(get("color")) ? get("color") : "#5267d8";
    await db.insert(jobs).values({ userId: u.id, name, hourlyRate: rate, color });
    return redirect("/jobs", ["success", "Job added."]);
  }
  const list = await db
    .select({
      id: jobs.id,
      name: jobs.name,
      hourlyRate: jobs.hourlyRate,
      color: jobs.color,
      active: jobs.active,
      shiftCount: sql<number>`count(${shifts.id})::int`,
    })
    .from(jobs)
    .leftJoin(shifts, eq(shifts.jobId, jobs.id))
    .where(eq(jobs.userId, u.id))
    .groupBy(jobs.id)
    .orderBy(desc(jobs.active), asc(jobs.name));

  const body = `
<div class="welcome-row"><div><h2>Manage your employers</h2><p>Each job can have its own hourly pay rate.</p></div></div>
<div class="two-col jobs-layout">
 <article class="panel"><div class="panel-head"><div><h3>Add a job</h3><p>Enter the employer and your base hourly rate.</p></div></div>
 <form method="post" class="form-stack"><label>Employer / job name<input name="name" placeholder="e.g. Retail job" required maxlength="80"></label><label>Hourly rate (CAD)<div class="input-prefix"><span>$</span><input name="hourly_rate" type="number" min="0" step="0.01" placeholder="18.00" required></div></label><label>Label colour<input type="color" name="color" value="#5267d8" class="color-input"></label><button class="button primary" type="submit">＋ Save job</button></form></article>
 <article class="panel"><div class="panel-head"><div><h3>Your jobs</h3><p>${list.length} job records</p></div></div>
 ${
   list.length
     ? `<div class="job-list">${list
         .map(
           (j) =>
             `<div class="job-row"><span class="job-color" style="background:${esc(j.color)}"></span><div class="job-info"><strong>${esc(j.name)}</strong><small>$${money(j.hourlyRate)}/hour · ${j.shiftCount} shifts</small></div><span class="status ${j.active ? "done" : "muted"}">${j.active ? "Active" : "Archived"}</span><div class="inline-actions"><form method="post" action="/jobs/${j.id}/toggle"><button class="text-button" title="Archive or activate">${j.active ? "Archive" : "Activate"}</button></form><form method="post" action="/jobs/${j.id}/delete" onsubmit="return confirm('Delete this job and all its shift records?')"><button class="text-button danger">Delete</button></form></div></div>`,
         )
         .join("")}</div>`
     : `<div class="empty-state compact"><strong>No jobs added</strong><p>Add your first employer using the form.</p></div>`
 }
 </article>
</div>`;
  return page(req, u, { title: "My Jobs", nav: "jobs", body });
}

async function clockPage(req: Request, u: User) {
  if (req.method === "POST") {
    const get = await formData(req);
    const action = get("action");
    const now = fmtLocal(localNow(req, get("client_now")));
    if (action === "in") {
      const jobId = parseInt(get("job_id"), 10);
      const [existing] = await db
        .select({ id: shifts.id })
        .from(shifts)
        .innerJoin(jobs, eq(jobs.id, shifts.jobId))
        .where(and(isNull(shifts.endTime), eq(jobs.userId, u.id)))
        .limit(1);
      if (existing) return redirect("/clock", ["error", "Clock out of the active shift before starting another."]);
      if (!(await ownJob(u, jobId))) return redirect("/clock", ["error", "Choose a job first."]);
      await db.insert(shifts).values({ jobId, startTime: now });
      return redirect("/clock", ["success", "Clocked in."]);
    }
    if (action === "out") {
      const shiftId = parseInt(get("shift_id"), 10);
      const breakMinutes = Math.max(0, parseInt(get("break_minutes"), 10) || 0);
      if (shiftId && (await ownShift(u, shiftId))) {
        await db.update(shifts).set({ endTime: now, breakMinutes }).where(and(eq(shifts.id, shiftId), isNull(shifts.endTime)));
      }
      return redirect("/clock", ["success", "Clocked out. Shift saved."]);
    }
    return redirect("/clock");
  }

  const [active] = await db.select(shiftSelect).from(shifts).innerJoin(jobs, eq(jobs.id, shifts.jobId)).where(and(isNull(shifts.endTime), eq(jobs.userId, u.id))).limit(1);
  const activeJobs = await db.select().from(jobs).where(and(eq(jobs.active, true), eq(jobs.userId, u.id))).orderBy(asc(jobs.name));
  const clientNow = `<input type="hidden" name="client_now" class="client-now">`;
  const inner = active
    ? `<span class="live-pill"><i></i> SHIFT IN PROGRESS</span><h2>${esc(active.jobName)}</h2><div class="timer" id="timer" data-start="${esc(active.startTime)}">00:00:00</div><p class="muted-text">Clocked in at ${esc(active.startTime.replace("T", " "))}</p>
 <form method="post" class="clock-out-form"><input type="hidden" name="action" value="out"><input type="hidden" name="shift_id" value="${active.id}">${clientNow}<label>Unpaid break (minutes)<input type="number" name="break_minutes" min="0" value="0"></label><button class="button danger-button" type="submit">■ Clock out</button></form>`
    : `<div class="clock-symbol">◷</div><h2>Ready to start?</h2><p class="muted-text">Choose which job you are working at.</p>
 ${
   activeJobs.length
     ? `<form method="post" class="clock-in-form"><input type="hidden" name="action" value="in">${clientNow}<label>Select job<select name="job_id" required><option value="">Choose a job...</option>${jobOptions(activeJobs)}</select></label><button class="button success-button" type="submit">▶ Clock in</button></form>`
     : `<div class="notice">Add a job before clocking in. <a href="/jobs">Go to My Jobs →</a></div>`
 }`;
  const body = `
<div class="welcome-row"><div><h2>Time clock</h2><p>Only one active shift can run at a time.</p></div></div>
<div class="clock-card">
 ${inner}
</div>
<div class="notice subtle">Clock-in and clock-out times use your device's local time. Verify entries before relying on them for payroll.</div>`;
  return page(req, u, { title: "Clock In / Out", nav: "clock", body });
}

async function timesheetsPage(req: Request, u: User) {
  const url = new URL(req.url);
  const start = url.searchParams.get("start") || "";
  const end = url.searchParams.get("end") || "";
  const jobId = url.searchParams.get("job_id") || "";
  const conds = [eq(jobs.userId, u.id)];
  if (/^\d{4}-\d{2}-\d{2}$/.test(start)) conds.push(gte(shifts.startTime, start));
  if (/^\d{4}-\d{2}-\d{2}$/.test(end)) conds.push(lte(shifts.startTime, end + "T99"));
  if (parseInt(jobId, 10)) conds.push(eq(shifts.jobId, parseInt(jobId, 10)));
  const rows: ShiftRow[] = await db
    .select(shiftSelect)
    .from(shifts)
    .innerJoin(jobs, eq(jobs.id, shifts.jobId))
    .where(and(...conds))
    .orderBy(desc(shifts.startTime));
  let totalHours = 0, totalPay = 0;
  const entries = rows.map((r) => {
    const hours = shiftHours(r), pay = shiftPay(r);
    totalHours += hours;
    totalPay += pay;
    return { ...r, hours, pay };
  });
  const allJobs = await db.select().from(jobs).where(eq(jobs.userId, u.id)).orderBy(asc(jobs.name));

  const body = `
<div class="welcome-row"><div><h2>Shift history</h2><p>Review, filter, and correct your recorded hours.</p></div><a class="button primary" href="/shift/new">＋ Add shift</a></div>
<article class="panel">
<form method="get" class="filters"><label>From<input type="date" name="start" value="${esc(start)}"></label><label>To<input type="date" name="end" value="${esc(end)}"></label><label>Job<select name="job_id"><option value="">All jobs</option>${allJobs
    .map((j) => `<option value="${j.id}" ${jobId === String(j.id) ? "selected" : ""}>${esc(j.name)}</option>`)
    .join("")}</select></label><button class="button secondary" type="submit">Filter</button><a class="text-button" href="/timesheets">Clear</a></form>
<div class="summary-strip"><div><small>Filtered hours</small><strong>${money(totalHours)} hrs</strong></div><div><small>Gross pay</small><strong>$${money(totalPay)}</strong></div><a class="button secondary" href="/export.csv">↓ Export all CSV</a></div>
<div class="table-scroll"><table><thead><tr><th>JOB</th><th>DATE</th><th>START</th><th>END</th><th>BREAK</th><th>HOURS</th><th>RATE</th><th>GROSS PAY</th><th></th></tr></thead><tbody>
${
  entries.length
    ? entries
        .map(
          (e) =>
            `<tr><td><span class="job-dot" style="background:${esc(e.color)}"></span><strong>${esc(e.jobName)}</strong></td><td>${esc(e.startTime.slice(0, 10))}</td><td>${esc(e.startTime.slice(11, 16))}</td><td>${e.endTime ? esc(e.endTime.slice(11, 16)) : "Open"}</td><td>${e.breakMinutes}m</td><td>${money(e.hours)}</td><td>$${money(e.hourlyRate)}</td><td><strong>$${money(e.pay)}</strong></td><td><div class="inline-actions"><a class="text-button" href="/shift/${e.id}/edit">Edit</a><form method="post" action="/shift/${e.id}/delete" onsubmit="return confirm('Delete this shift?')"><button class="text-button danger">Delete</button></form></div></td></tr>`,
        )
        .join("")
    : `<tr><td colspan="9" class="empty-cell">No shifts match these filters.</td></tr>`
}
</tbody></table></div></article>`;
  return page(req, u, { title: "Timesheets", nav: "timesheets", body });
}

function parseShiftForm(get: (k: string) => string) {
  const jobId = parseInt(get("job_id"), 10);
  const startRaw = get("start_time");
  const endRaw = get("end_time");
  const breaks = get("break_minutes") === "" ? 0 : Number(get("break_minutes"));
  if (!jobId || !LOCAL_RE.test(startRaw) || (endRaw && !LOCAL_RE.test(endRaw))) return null;
  if (!Number.isInteger(breaks) || breaks < 0) return null;
  const startTime = startRaw.slice(0, 16);
  const endTime = endRaw ? endRaw.slice(0, 16) : null;
  if (Number.isNaN(toEpoch(startTime)) || (endTime && (Number.isNaN(toEpoch(endTime)) || toEpoch(endTime) <= toEpoch(startTime)))) return null;
  return { jobId, startTime, endTime, breakMinutes: breaks, notes: get("notes").trim() };
}

function shiftFormPage(req: Request, u: User, list: Job[], shift?: typeof shifts.$inferSelect) {
  const t = shift ? "Edit shift" : "Add shift";
  const body = `
<div class="form-page"><article class="panel"><div class="panel-head"><div><h3>${shift ? "Update shift details" : "Manual shift entry"}</h3><p>Enter the date and time from your work record.</p></div></div>
<form method="post" class="form-stack">
<label>Job<select name="job_id" required>${jobOptions(list, shift?.jobId)}</select></label>
<label>Clock-in date and time<input type="datetime-local" name="start_time" value="${shift ? esc(shift.startTime.slice(0, 16)) : ""}" required></label>
<label>Clock-out date and time <small>(leave empty for an open shift)</small><input type="datetime-local" name="end_time" value="${shift?.endTime ? esc(shift.endTime.slice(0, 16)) : ""}"></label>
<label>Unpaid break (minutes)<input type="number" name="break_minutes" min="0" value="${shift ? shift.breakMinutes : 0}"></label>
<label>Notes<textarea name="notes" rows="3" placeholder="Optional notes">${shift ? esc(shift.notes) : ""}</textarea></label>
<div class="form-actions"><a class="button secondary" href="/timesheets">Cancel</a><button class="button primary" type="submit">Save shift</button></div>
</form></article></div>`;
  return page(req, u, { title: t, nav: "timesheets", body });
}

async function newShift(req: Request, u: User) {
  if (req.method === "POST") {
    const data = parseShiftForm(await formData(req));
    if (!data || !(await ownJob(u, data.jobId))) return redirect("/shift/new", ["error", "Check the job, date/time values, and break duration."]);
    await db.insert(shifts).values(data);
    return redirect("/timesheets", ["success", "Shift entry saved."]);
  }
  const list = await db.select().from(jobs).where(and(eq(jobs.active, true), eq(jobs.userId, u.id))).orderBy(asc(jobs.name));
  return shiftFormPage(req, u, list);
}

async function editShift(req: Request, u: User, id: number) {
  const shift = await ownShift(u, id);
  if (!shift) return redirect("/timesheets");
  if (req.method === "POST") {
    const data = parseShiftForm(await formData(req));
    if (!data || !(await ownJob(u, data.jobId))) return redirect(`/shift/${id}/edit`, ["error", "Check the entered values."]);
    await db.update(shifts).set(data).where(eq(shifts.id, id));
    return redirect("/timesheets", ["success", "Shift updated."]);
  }
  const list = await db.select().from(jobs).where(eq(jobs.userId, u.id)).orderBy(asc(jobs.name));
  return shiftFormPage(req, u, list, shift);
}

async function reportsPage(req: Request, u: User) {
  const allJobs = await db.select().from(jobs).where(eq(jobs.userId, u.id)).orderBy(asc(jobs.name));
  const done = (
    await db
      .select({ shift: shifts })
      .from(shifts)
      .innerJoin(jobs, eq(jobs.id, shifts.jobId))
      .where(and(sql`${shifts.endTime} is not null`, eq(jobs.userId, u.id)))
  ).map((r) => r.shift);
  const report = allJobs.map((j) => {
    const js = done.filter((s) => s.jobId === j.id);
    const hours = round2(js.reduce((a, s) => a + shiftHours(s), 0));
    return { name: j.name, rate: j.hourlyRate, shifts: js.length, hours, pay: round2(hours * j.hourlyRate) };
  });
  const totalHours = report.reduce((a, r) => a + r.hours, 0);
  const totalPay = report.reduce((a, r) => a + r.pay, 0);
  const body = `
<div class="welcome-row"><div><h2>All-time job summary</h2><p>Completed shifts grouped by employer.</p></div><a class="button secondary" href="/export.csv">↓ Export CSV</a></div>
<div class="stats-grid two-stats"><article class="stat-card"><div class="stat-label">Total recorded hours</div><div class="stat-value">${money(totalHours)} <small>hrs</small></div><div class="stat-foot">Completed shifts only</div></article><article class="stat-card"><div class="stat-label">Total gross earnings</div><div class="stat-value">$${money(totalPay)}</div><div class="stat-foot">Before taxes and deductions · CAD</div></article></div>
<article class="panel"><div class="panel-head"><div><h3>Breakdown by job</h3><p>Based on each job's current hourly rate.</p></div></div><div class="table-scroll"><table><thead><tr><th>JOB</th><th>HOURLY RATE</th><th>SHIFTS</th><th>TOTAL HOURS</th><th>GROSS PAY</th></tr></thead><tbody>${
    report.length
      ? report
          .map((r) => `<tr><td><strong>${esc(r.name)}</strong></td><td>$${money(r.rate)}</td><td>${r.shifts}</td><td>${money(r.hours)}</td><td><strong>$${money(r.pay)}</strong></td></tr>`)
          .join("")
      : `<tr><td colspan="5" class="empty-cell">Add jobs and shifts to generate reports.</td></tr>`
  }</tbody></table></div></article>
<div class="notice subtle">Historical earnings are recalculated using each job's current hourly rate. If your pay rate changes, the old shifts will also reflect the new rate in reports. For accurate historical payroll, avoid changing a job's rate after recording shifts.</div>`;
  return page(req, u, { title: "Reports", nav: "reports", body });
}

async function exportCsv(u: User) {
  const rows: ShiftRow[] = await db.select(shiftSelect).from(shifts).innerJoin(jobs, eq(jobs.id, shifts.jobId)).where(eq(jobs.userId, u.id)).orderBy(desc(shifts.startTime));
  const cell = (v: unknown) => {
    const s = String(v ?? "");
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [["Job", "Date", "Clock In", "Clock Out", "Break Minutes", "Hours", "Hourly Rate CAD", "Gross Pay CAD", "Notes"]];
  for (const s of rows) {
    lines.push([
      s.jobName,
      s.startTime.slice(0, 10),
      s.startTime.slice(11, 16),
      s.endTime ? s.endTime.slice(11, 16) : "OPEN",
      String(s.breakMinutes),
      String(shiftHours(s)),
      String(s.hourlyRate),
      String(shiftPay(s)),
      s.notes,
    ]);
  }
  return new Response(lines.map((l) => l.map(cell).join(",")).join("\r\n") + "\r\n", {
    headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": "attachment; filename=work-timesheet.csv", "Cache-Control": "no-store" },
  });
}

async function apiStatus(req: Request, u: User) {
  const [active] = await db.select(shiftSelect).from(shifts).innerJoin(jobs, eq(jobs.id, shifts.jobId)).where(and(isNull(shifts.endTime), eq(jobs.userId, u.id))).limit(1);
  return Response.json({ active: active ?? null, server_time: new Date().toISOString(), local_time: fmtLocal(localNow(req)) });
}

// ---------- profile ----------

async function checkPassword(u: User, password: string) {
  const [row] = await db.select({ passwordHash: users.passwordHash }).from(users).where(eq(users.id, u.id)).limit(1);
  return !!row && (await verifyPassword(password, row.passwordHash));
}

async function profilePage(req: Request, u: User) {
  const [stats] = await db
    .select({
      jobCount: sql<number>`count(distinct ${jobs.id})::int`,
      shiftCount: sql<number>`count(${shifts.id})::int`,
    })
    .from(jobs)
    .leftJoin(shifts, eq(shifts.jobId, jobs.id))
    .where(eq(jobs.userId, u.id));
  const [sess] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(sessions)
    .where(and(eq(sessions.userId, u.id), gte(sessions.expiresAt, new Date())));
  const otherSessions = Math.max(0, (sess?.n ?? 1) - 1);
  const since = `${MONTHS[u.createdAt.getUTCMonth()]} ${u.createdAt.getUTCDate()}, ${u.createdAt.getUTCFullYear()}`;
  const userPattern = 'minlength="3" maxlength="32" pattern="[A-Za-z0-9_.\\-]{3,32}" title="3–32 characters: letters, numbers, dots, dashes or underscores"';

  const body = `
<div class="welcome-row"><div><h2>Your profile</h2><p>Update your account details and security settings.</p></div></div>
<article class="panel profile-card">
 <div class="profile-avatar">${esc(u.username.slice(0, 2).toUpperCase())}</div>
 <div class="profile-meta"><h3>${esc(u.username)}</h3><p>Member since ${since}</p></div>
 <div class="profile-stats"><div><strong>${stats?.jobCount ?? 0}</strong><small>Jobs</small></div><div><strong>${stats?.shiftCount ?? 0}</strong><small>Shifts</small></div><div><strong>${otherSessions + 1}</strong><small>Active sessions</small></div></div>
</article>
<div class="two-col profile-grid">
 <article class="panel"><div class="panel-head"><div><h3>Change username</h3><p>This is the name you use to log in.</p></div></div>
  <form method="post" action="/profile/username" class="form-stack">
   <label>New username<input name="username" value="${esc(u.username)}" autocomplete="username" required ${userPattern}></label>
   <label>Current password<input type="password" name="current_password" autocomplete="current-password" required></label>
   <div class="form-actions"><button class="button primary" type="submit">Save username</button></div>
  </form>
 </article>
 <article class="panel"><div class="panel-head"><div><h3>Change password</h3><p>Other devices are signed out when you change it.</p></div></div>
  <form method="post" action="/profile/password" class="form-stack">
   <input type="text" name="username" value="${esc(u.username)}" autocomplete="username" hidden>
   <label>Current password<input type="password" name="current_password" autocomplete="current-password" required></label>
   <label>New password <small>(at least 8 characters)</small><input type="password" name="password" autocomplete="new-password" required minlength="8" maxlength="200"></label>
   <label>Confirm new password<input type="password" name="confirm" autocomplete="new-password" required minlength="8" maxlength="200"></label>
   <div class="form-actions"><button class="button primary" type="submit">Update password</button></div>
  </form>
 </article>
</div>
<article class="panel"><div class="panel-head"><div><h3>Sessions</h3><p>${otherSessions ? `You're also signed in on ${otherSessions} other device${otherSessions === 1 ? "" : "s"} or browser${otherSessions === 1 ? "" : "s"}.` : "This is the only device signed in to your account."}</p></div>
  <form method="post" action="/profile/sessions"><button class="button secondary" type="submit" ${otherSessions ? "" : "disabled"}>Sign out other devices</button></form></div>
</article>
<article class="panel danger-zone"><div class="panel-head"><div><h3>Delete account</h3><p>Permanently removes your account and all of its jobs and shifts. This can't be undone.</p></div></div>
  <form method="post" action="/profile/delete" class="form-stack delete-form" onsubmit="return confirm('Delete your account and all of its data permanently?')">
   <label>Type your username to confirm<input name="confirm_username" autocomplete="off" required placeholder="${esc(u.username)}"></label>
   <label>Current password<input type="password" name="current_password" autocomplete="current-password" required></label>
   <div class="form-actions"><button class="button danger-button" type="submit">Delete my account</button></div>
  </form>
</article>`;
  return page(req, u, { title: "Profile", nav: "profile", body });
}

async function profileUsername(req: Request, u: User) {
  const get = await formData(req);
  const username = get("username").trim().toLowerCase();
  if (!USERNAME_RE.test(username)) return redirect("/profile", ["error", "Username must be 3–32 characters: letters, numbers, dots, dashes or underscores."]);
  if (!(await checkPassword(u, get("current_password")))) return redirect("/profile", ["error", "Your current password is incorrect."]);
  if (username === u.username) return redirect("/profile", ["success", "Username unchanged."]);
  const [taken] = await db.select({ id: users.id }).from(users).where(and(sql`lower(${users.username}) = ${username}`, ne(users.id, u.id))).limit(1);
  if (taken) return redirect("/profile", ["error", "That username is already taken."]);
  try {
    await db.update(users).set({ username }).where(eq(users.id, u.id));
  } catch {
    return redirect("/profile", ["error", "That username is already taken."]);
  }
  return redirect("/profile", ["success", `Username changed to ${username}.`]);
}

async function profilePassword(req: Request, u: User) {
  const get = await formData(req);
  const password = get("password");
  if (!(await checkPassword(u, get("current_password")))) return redirect("/profile", ["error", "Your current password is incorrect."]);
  if (password.length < 8 || password.length > 200) return redirect("/profile", ["error", "New password must be at least 8 characters."]);
  if (password !== get("confirm")) return redirect("/profile", ["error", "The two new passwords don't match."]);
  await db.update(users).set({ passwordHash: await hashPassword(password) }).where(eq(users.id, u.id));
  await db.delete(sessions).where(and(eq(sessions.userId, u.id), ne(sessions.tokenHash, u.tokenHash)));
  return redirect("/profile", ["success", "Password updated. Other devices have been signed out."]);
}

async function profileSessions(u: User) {
  await db.delete(sessions).where(and(eq(sessions.userId, u.id), ne(sessions.tokenHash, u.tokenHash)));
  return redirect("/profile", ["success", "Signed out of all other devices."]);
}

async function profileDelete(req: Request, u: User) {
  const get = await formData(req);
  if (get("confirm_username").trim().toLowerCase() !== u.username.toLowerCase()) return redirect("/profile", ["error", "The username you typed doesn't match your account."]);
  if (!(await checkPassword(u, get("current_password")))) return redirect("/profile", ["error", "Your current password is incorrect."]);
  await db.delete(users).where(eq(users.id, u.id)); // jobs, shifts and sessions cascade
  const res = redirect("/login", ["success", "Your account has been deleted."]);
  res.headers.append("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${isSecure(req) ? "; Secure" : ""}`);
  return res;
}

function notFound(req: Request, u: User) {
  const body = `<div class="empty-state"><div class="empty-icon">?</div><strong>Page not found</strong><p>That page doesn't exist. <a href="/">Back to the dashboard →</a></p></div>`;
  return page(req, u, { title: "Not found", nav: "", body, status: 404 });
}

// ---------- router ----------

export default async (req: Request) => {
  const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
  const m = req.method;
  let match: RegExpMatchArray | null;

  if (path === "/login" && (m === "GET" || m === "POST")) {
    if (m === "GET" && (await currentUser(req))) return redirect("/");
    return loginRoute(req);
  }
  if (path === "/signup" && (m === "GET" || m === "POST")) {
    if (m === "GET" && (await currentUser(req))) return redirect("/");
    return signupRoute(req);
  }
  if (path === "/logout" && m === "POST") return logoutRoute(req);

  const u = await currentUser(req);
  if (!u) {
    if (path.startsWith("/api/")) return Response.json({ error: "Not logged in" }, { status: 401 });
    return redirect("/login");
  }

  if (path === "/" && m === "GET") return dashboard(req, u);
  if (path === "/jobs" && (m === "GET" || m === "POST")) return jobsPage(req, u);
  if ((match = path.match(/^\/jobs\/(\d+)\/toggle$/)) && m === "POST") {
    await db.update(jobs).set({ active: sql`not ${jobs.active}` }).where(and(eq(jobs.id, Number(match[1])), eq(jobs.userId, u.id)));
    return redirect("/jobs");
  }
  if ((match = path.match(/^\/jobs\/(\d+)\/delete$/)) && m === "POST") {
    await db.delete(jobs).where(and(eq(jobs.id, Number(match[1])), eq(jobs.userId, u.id)));
    return redirect("/jobs", ["success", "Job and its shifts deleted."]);
  }
  if (path === "/clock" && (m === "GET" || m === "POST")) return clockPage(req, u);
  if (path === "/timesheets" && m === "GET") return timesheetsPage(req, u);
  if (path === "/shift/new" && (m === "GET" || m === "POST")) return newShift(req, u);
  if ((match = path.match(/^\/shift\/(\d+)\/edit$/)) && (m === "GET" || m === "POST")) return editShift(req, u, Number(match[1]));
  if ((match = path.match(/^\/shift\/(\d+)\/delete$/)) && m === "POST") {
    const id = Number(match[1]);
    if (await ownShift(u, id)) await db.delete(shifts).where(eq(shifts.id, id));
    return redirect("/timesheets", ["success", "Shift deleted."]);
  }
  if (path === "/reports" && m === "GET") return reportsPage(req, u);
  if (path === "/export.csv" && m === "GET") return exportCsv(u);
  if (path === "/api/status" && m === "GET") return apiStatus(req, u);
  if (path === "/profile" && m === "GET") return profilePage(req, u);
  if (path === "/profile/username" && m === "POST") return profileUsername(req, u);
  if (path === "/profile/password" && m === "POST") return profilePassword(req, u);
  if (path === "/profile/sessions" && m === "POST") return profileSessions(u);
  if (path === "/profile/delete" && m === "POST") return profileDelete(req, u);
  return notFound(req, u);
};

export const config: Config = {
  path: ["/", "/*"],
  excludedPath: ["/static/*"],
  preferStatic: true,
};
