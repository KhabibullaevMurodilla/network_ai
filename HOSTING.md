# Put it online

## Option A (easiest, free, no backend): GitHub Pages demo
Serves the landing page, `/analyze`, `/demo` and the **full dashboard in local mode**: visitors import their own pcap/CSV and the dashboard runs on a database kept in their own browser (IndexedDB). No Supabase, no sign-in, no backend. Server-only features (alert delivery, response actions, team, API keys, PDF report, SNMP physical map) are not on this site; see README "v6.9".
1. Push the repo to GitHub (public).
2. Repo -> Settings -> Pages -> Source: **GitHub Actions**.
3. The `Deploy demo to GitHub Pages` workflow runs on every push to `main`; the site appears at
   `https://<username>.github.io/<repo-name>/` (dashboard: `/dashboard/import/`).
To refresh the snapshot: `cd backend && python scripts/export_demo_snapshot.py`, then commit `frontend/public/demo-data/`.
Tested locally (static build served under the repo sub-path, page renders the data); the GitHub workflow itself has not been run.

## Option B: full working app (signed-in dashboard) with Supabase + Render + Vercel

Order matters: database first, then backend, then frontend (the frontend needs the backend's address at build time).

## 1. Supabase (you already have this)
Run `supabase/schema.sql` once in the SQL editor (it is re-runnable). Note your project URL, publishable key and the legacy `service_role` key.

## 2. Backend on Render
1. render.com -> New -> Web Service -> connect the GitHub repo.
2. Runtime **Docker**, Root Directory `backend`, instance type Free.
3. Environment variables:
   - `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` (the `eyJ...` legacy key worked for you)
   - `ALLOWED_ORIGINS` = your Vercel address (set after step 3, then redeploy), e.g. `https://your-app.vercel.app`
   - `DEMO_TENANT_ID` = any UUID you choose (generate one at uuidgenerator.net)
4. Deploy, then open `https://YOUR-SERVICE.onrender.com/health` -> `{"status":"ok"}`.
Free services sleep after ~15 min idle; the first visit then takes 30-60 s.

## 3. Frontend on Vercel
1. vercel.com -> Add New Project -> import the repo, **Root Directory `frontend`**.
2. Environment variables (these are baked in at build time):
   - `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` (publishable key)
   - `NEXT_PUBLIC_API_URL` = the Render address from step 2 (no trailing slash)
3. Deploy. Copy the Vercel address into Render's `ALLOWED_ORIGINS` and redeploy the backend.
4. Supabase -> Authentication -> URL Configuration: add the Vercel address as Site URL.

## 4. Seed the public demo (from your PC, once)
```
cd backend
pip install -r requirements.txt
set SUPABASE_URL=...            (PowerShell: $env:SUPABASE_URL="...")
set SUPABASE_SERVICE_ROLE_KEY=...
set DEMO_TENANT_ID=<the same UUID as on Render>
python scripts/seed_demo_tenant.py
```
Then open `https://YOUR-APP.vercel.app/demo`. This path was only tested against the
in-memory test database, so check the page and tell me what you see.

## 5. Put the link in the README
Replace the "Live demo" placeholder at the top of README.md.

## Before you invite real users
- Sign-up emails come from Supabase's default sender (rate-limited); configure SMTP for real use.
- Don't enable Stripe billing until you have tested a real payment end to end.
- Stream tokens appear in server logs (known issue, not yet fixed).
