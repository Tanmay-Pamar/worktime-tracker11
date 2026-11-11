# WorkTime — Multi-Job Clock In/Out System

A web app for tracking shifts across multiple jobs, calculating gross earnings in CAD, and viewing dashboard summaries. It runs on Netlify: pages are served by a Netlify Function and data is stored in Netlify Database (managed Postgres).

## Features
- Multiple employers with separate hourly rates and colour labels.
- Clock in and clock out with a live elapsed-time display.
- One active shift at a time to prevent overlapping clock sessions.
- Record unpaid break minutes.
- Manually add, edit, and delete past shifts.
- Filter timesheets by date range and job.
- Dashboard totals for current month and current week.
- Job earnings chart and all-time report.
- Export all shift records to CSV.
- Profile page to change your username or password, sign out other devices, or delete your account.

## Project layout
- `netlify/functions/app.mts` — renders every page and handles form actions.
- `db/schema.ts` — database tables (jobs, shifts).
- `netlify/database/migrations/` — generated SQL migrations, applied automatically on deploy.
- `public/static/` — stylesheet and browser script.

## Running locally
```bash
npm install
netlify dev
```

## Accounts
Every page needs a login. Visitors who aren't logged in are sent to `/login`, and new people can create their own account at `/signup`. Each account sees only its own jobs, shifts, reports and CSV export. Passwords are stored as salted scrypt hashes, and sessions last 30 days or until **Log out** is used.

An `admin` account is created by a database migration, and the jobs and shifts that existed before accounts were added belong to it.

## First use
1. Log in, or sign up for a new account.
2. Open **My Jobs** and add each employer with its hourly rate.
3. Open **Clock In / Out**, select the job, and clock in.
4. Clock out at the end of the shift and enter unpaid break minutes.
5. Use **Timesheets** to correct entries or add earlier shifts.
6. Use **Reports** or **Export CSV** to review totals.

## Important limitations
- Anyone can sign up for an account, but no account can see another account's data. Passwords can be changed from **Profile**, but there is no reset for a forgotten password yet.
- Times use the local clock of the device you're using.
- Earnings are gross estimates before tax, CPP, EI, vacation pay, and other deductions.
- Current hourly rates are used when calculating historical shifts. If your rate changes, prior shift earnings will also change. Consider adding a separate job record for a new rate.
- Overtime is not automatically calculated.
- For payroll records, verify entries against employer timesheets and pay statements.
