# ForeScout findings app

A Postgres database of the ForeScout device security findings, with a Node.js (Express) web dashboard. It's built to deploy on [Railway](https://railway.com).

## What's in it

| Path | Purpose |
|---|---|
| `db/schema.sql` | Tables: `summary_metrics`, `findings`, `control_coverage`, `device_mix`, `legacy_hosts`, `imports` |
| `data/*.json` | Findings data computed from the ForeScout host export (8 Oct 2026, demo lab) |
| `scripts/build_data.py` | Rebuilds `data/*.json` from a new ForeScout CSV export |
| `scripts/migrate.js` | Creates the tables. Seeds them if the database is empty. Runs on every start. |
| `scripts/seed.js` | Loads `data/*.json`. Re-running refreshes the counts and keeps status and owner. |
| `server.js` | API and static frontend |
| `public/` | Dashboard page: headline figures, findings by area, action plan, control coverage, device mix, legacy hosts |

### API

- `GET /api/summary`, `/api/findings?pillar=…`, `/api/coverage`, `/api/devices`, `/api/legacy?q=…`
- `PATCH /api/findings/:id` with `{"status": "In progress", "owner": "OT team"}` and header `X-Edit-Token`. This only works when `EDIT_TOKEN` is set.
- `GET /healthz` checks the database connection.

## Deploy on Railway

1. In Railway, create a project and add a **PostgreSQL** database.
2. Add a service from this GitHub repo and set its **Root Directory** to `findings-app`. Railway reads `railway.json` and runs `npm start`.
3. In the service's **Variables**, add:
   - `DATABASE_URL` = `${{Postgres.DATABASE_URL}}` (a reference to the database service)
   - `EDIT_TOKEN` (optional): a long random string. It turns on status and owner editing in the action plan.
   - `BASIC_AUTH` (optional): `user:password`. It puts the whole site behind a sign-in, which is worth doing because the data includes host names and IPs.
4. Deploy, then generate a public domain under **Settings → Networking**.

On first start the app creates the tables and loads the findings. Later deploys leave existing data alone.

With the Railway CLI instead (run from `findings-app/`):

```bash
railway login
railway init                       # or: railway link
railway add --database postgres
railway up
railway variables --set 'DATABASE_URL=${{Postgres.DATABASE_URL}}'
```

## Refresh the data from a new export

```bash
python3 scripts/build_data.py /path/to/Hosts_export.csv data
railway run npm run seed           # or set DATABASE_URL and run: npm run seed
```

## Run locally

```bash
npm install
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/findings
npm start                          # http://localhost:3000
```

Set `PGSSL=true` when connecting to a database that requires TLS. Railway's public proxy URLs are detected automatically.
