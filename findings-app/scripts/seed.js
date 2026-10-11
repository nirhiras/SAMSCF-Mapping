// Loads data/*.json into Postgres. Re-running refreshes the counts but keeps
// each finding's remediation status and owner.
const fs = require('fs');
const path = require('path');
const { pool } = require('../db');

const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const load = (name) => JSON.parse(fs.readFileSync(path.join(dataDir, `${name}.json`), 'utf8'));

async function seed() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const r of load('summary')) {
      await client.query(
        `INSERT INTO summary_metrics (metric, label, value) VALUES ($1, $2, $3)
         ON CONFLICT (metric) DO UPDATE SET label = EXCLUDED.label, value = EXCLUDED.value`,
        [r.metric, r.label, r.value]);
    }

    for (const r of load('findings')) {
      await client.query(
        `INSERT INTO findings (id, pillar, finding, affected, unverified, severity, priority, next_step)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO UPDATE SET pillar = EXCLUDED.pillar, finding = EXCLUDED.finding,
           affected = EXCLUDED.affected, unverified = EXCLUDED.unverified, severity = EXCLUDED.severity,
           priority = EXCLUDED.priority, next_step = EXCLUDED.next_step`,
        [r.id, r.pillar, r.finding, r.affected, r.unverified, r.severity, r.priority, r.next_step]);
    }

    for (const r of load('coverage')) {
      await client.query(
        `INSERT INTO control_coverage (id, area, control, covered, total, note) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO UPDATE SET area = EXCLUDED.area, control = EXCLUDED.control,
           covered = EXCLUDED.covered, total = EXCLUDED.total, note = EXCLUDED.note`,
        [r.id, r.area, r.control, r.covered, r.total, r.note]);
    }

    // Device mix and legacy hosts are snapshots: replace them wholesale.
    await client.query('DELETE FROM device_mix');
    for (const r of load('devices')) {
      await client.query('INSERT INTO device_mix (type, hosts) VALUES ($1, $2)', [r.type, r.hosts]);
    }
    await client.query('DELETE FROM legacy_hosts');
    for (const r of load('legacy')) {
      await client.query(
        'INSERT INTO legacy_hosts (id, host, ip, function, os, segment, purdue) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [r.id, r.host, r.ip, r.function, r.os, r.segment, r.purdue]);
    }

    await client.query('INSERT INTO imports (source) VALUES ($1)', [path.resolve(dataDir)]);
    await client.query('COMMIT');
    console.log('Seed complete');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { seed };

if (require.main === module) {
  seed()
    .then(() => pool.end())
    .catch((err) => { console.error(err); process.exit(1); });
}
