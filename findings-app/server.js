const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { pool } = require('./db');

const app = express();
app.use(express.json({ limit: '16kb' }));

const STATUSES = ['Open', 'In progress', 'Done', 'Accepted risk'];
const EDIT_TOKEN = process.env.EDIT_TOKEN || '';
const BASIC_AUTH = process.env.BASIC_AUTH || ''; // "user:password"

const safeEqual = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

app.get('/healthz', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

// Optional site-wide password, since the data includes host names and IPs.
if (BASIC_AUTH) {
  app.use((req, res, next) => {
    const [scheme, encoded] = (req.headers.authorization || '').split(' ');
    const given = scheme === 'Basic' && encoded ? Buffer.from(encoded, 'base64').toString() : '';
    if (safeEqual(given, BASIC_AUTH)) return next();
    res.set('WWW-Authenticate', 'Basic realm="Findings"').status(401).send('Sign in required');
  });
}

app.use(express.static(path.join(__dirname, 'public')));

const route = (fn) => (req, res) => fn(req, res).catch((err) => {
  console.error(err);
  res.status(500).json({ error: 'Database error' });
});

app.get('/api/config', (_req, res) => res.json({ editable: Boolean(EDIT_TOKEN), statuses: STATUSES }));

app.get('/api/summary', route(async (_req, res) => {
  const [metrics, imp] = await Promise.all([
    pool.query('SELECT metric, label, value FROM summary_metrics'),
    pool.query('SELECT imported_at FROM imports ORDER BY id DESC LIMIT 1'),
  ]);
  res.json({
    metrics: Object.fromEntries(metrics.rows.map((r) => [r.metric, { label: r.label, value: r.value }])),
    importedAt: imp.rows[0]?.imported_at ?? null,
  });
}));

app.get('/api/findings', route(async (req, res) => {
  const pillar = typeof req.query.pillar === 'string' && req.query.pillar !== 'all' ? req.query.pillar : null;
  const { rows } = await pool.query(
    `SELECT id, pillar, finding, affected, unverified, severity, priority, next_step, status, owner, updated_at
       FROM findings
      WHERE ($1::text IS NULL OR pillar = $1)
      ORDER BY priority, affected DESC`, [pillar]);
  res.json(rows);
}));

app.patch('/api/findings/:id', route(async (req, res) => {
  if (!EDIT_TOKEN) return res.status(403).json({ error: 'Editing is turned off. Set EDIT_TOKEN to enable it.' });
  if (!safeEqual(req.get('x-edit-token') || '', EDIT_TOKEN)) return res.status(401).json({ error: 'Edit token is wrong.' });
  const { status, owner } = req.body || {};
  if (status !== undefined && !STATUSES.includes(status)) return res.status(400).json({ error: `Status must be one of: ${STATUSES.join(', ')}` });
  if (owner !== undefined && owner !== null && (typeof owner !== 'string' || owner.length > 100)) return res.status(400).json({ error: 'Owner must be text up to 100 characters.' });
  const { rows } = await pool.query(
    `UPDATE findings
        SET status = COALESCE($2, status),
            owner = CASE WHEN $3 THEN NULLIF(trim($4), '') ELSE owner END,
            updated_at = now()
      WHERE id = $1
      RETURNING id, status, owner, updated_at`,
    [req.params.id, status ?? null, owner !== undefined, owner ?? null]);
  if (!rows.length) return res.status(404).json({ error: 'Finding not found.' });
  res.json(rows[0]);
}));

app.get('/api/coverage', route(async (_req, res) => {
  const { rows } = await pool.query(
    'SELECT id, area, control, covered, total, note FROM control_coverage ORDER BY covered::float / NULLIF(total, 0) NULLS FIRST');
  res.json(rows);
}));

app.get('/api/devices', route(async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT type, hosts FROM device_mix ORDER BY (type = 'Not classified'), hosts DESC");
  res.json(rows);
}));

app.get('/api/legacy', route(async (req, res) => {
  const q = typeof req.query.q === 'string' && req.query.q.trim() ? `%${req.query.q.trim()}%` : null;
  const { rows } = await pool.query(
    `SELECT id, host, ip, function, os, segment, purdue FROM legacy_hosts
      WHERE $1::text IS NULL OR concat_ws(' ', host, ip, function, os, segment, purdue) ILIKE $1
      ORDER BY purdue, host`, [q]);
  res.json(rows);
}));

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`Findings app listening on port ${port}`));
