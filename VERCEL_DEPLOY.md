# Vercel Deployment Guide — 404 Web Vulnerability Scanner

## Overview

This guide walks you through deploying the 404 Scanner to Vercel so that both
the backend (Express, as serverless functions) and the frontend (static HTML/CSS/JS)
are served from the same domain under `/api/*`.

---

## What Was Changed

| File | Change |
|------|--------|
| `api/index.js` | **New** — exports the Express app as a Vercel serverless function |
| `vercel.json` | **New** — routes `/api/*` to the function; serves `docs/` as static files |
| `server.js` | Added `cors` middleware; `app.listen()` only runs when executed directly (not when imported) |
| `package.json` | Added `cors` dependency |

> **Note:** `docs/script.js` already used relative `/api/...` paths — no changes needed.

---

## Prerequisites

- A [Vercel account](https://vercel.com/signup) (free tier works)
- Project pushed to GitHub at `AgamSandhu-cysec/404-scanner`
- Supabase project with `SUPABASE_URL` and `SUPABASE_ANON_KEY` values ready

---

## Step 1 — Install the new dependency locally

```bash
cd /home/kali/Desktop/replitzip
npm install cors
```

Then commit everything:

```bash
git add api/index.js vercel.json server.js package.json package-lock.json
git commit -m "chore: prepare for Vercel deployment"
git push origin main
```

---

## Step 2 — Import the project on Vercel

1. Go to [https://vercel.com/new](https://vercel.com/new)
2. Click **"Import Git Repository"**
3. Select **`AgamSandhu-cysec/404-scanner`** from the list (authorize Vercel to access GitHub if prompted)
4. Leave the **Framework Preset** as **Other**
5. Leave **Root Directory** blank (project root)
6. **Do NOT** override the build/output settings — they are handled by `vercel.json`

---

## Step 3 — Set Environment Variables

Before deploying, add your secrets in the Vercel dashboard:

1. In the import wizard, click **"Environment Variables"**
   (or go to **Project → Settings → Environment Variables** after creation)
2. Add the following:

| Name | Value |
|------|-------|
| `SUPABASE_URL` | Your Supabase project URL (e.g. `https://xxxx.supabase.co`) |
| `SUPABASE_ANON_KEY` | Your Supabase anonymous key |

> ⚠️ **Never commit your `.env` file.** It is already excluded by `.gitignore`.
> The Drana Infinity AI runs locally only — do not add any `OLLAMA_*` keys to Vercel.

---

## Step 4 — Deploy

Click **"Deploy"**. Vercel will:
1. Install Node.js dependencies (`npm install`)
2. Build the serverless function from `api/index.js`
3. Serve `docs/` as static files

The deployment typically takes 1–3 minutes. You'll receive a URL like:
```
https://404-scanner-xxxx.vercel.app
```

---

## Step 5 — Verify

Visit your Vercel URL and test:

- [ ] Frontend loads (index.html from `docs/`)
- [ ] Quick Scan works (`POST /api/scan`)
- [ ] Active OWASP Scan streaming works (`GET /api/active-scan`)
- [ ] Directory Fuzzer works (`POST /api/fuzz-start`, `GET /api/fuzz-stream/:id`)
- [ ] Traffic Analyzer works (`POST /api/analyze-request`)
- [ ] Recent Scans sidebar loads from Supabase (`GET /api/recent-scans`)
- [ ] PDF Report generation works (`POST /api/report`)

---

## Local Development (unchanged)

The server still works locally as before:

```bash
node server.js
# or
npm run start
```

The `app.listen()` call only runs when `server.js` is executed directly
(not when imported by Vercel's `api/index.js`).

---

## Limitations on Vercel

| Feature | Status |
|---------|--------|
| Quick Scan, OWASP Check, Traffic Analyzer, PDF Report | ✅ Works |
| Directory Fuzzer | ✅ Works (per-request, stateless) |
| Supabase DB features | ✅ Works (set env vars) |
| Active OWASP Scan (SSE streaming) | ⚠️ Works but limited to Vercel's 10-second function timeout on free tier |
| Fuzzer SSE streaming | ⚠️ Same 10-second limit; large wordlists may timeout |
| Drana Infinity AI | ❌ Local only — will show "Ollama not installed" on Vercel (expected) |

> **Tip:** To avoid SSE timeout issues, upgrade to Vercel Pro (60-second limit)
> or deploy the backend to Railway/Render while keeping the frontend on Vercel.

---

## Re-deploying

Vercel automatically re-deploys on every `git push` to `main`.
To trigger a manual redeploy: **Vercel Dashboard → Deployments → Redeploy**.
