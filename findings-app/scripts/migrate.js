// Creates tables, then seeds them from data/*.json if the findings table is empty.
const fs = require('fs');
const path = require('path');
const { pool } = require('../db');
const { seed } = require('./seed');

async function main() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
  await pool.query(sql);
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM findings');
  if (rows[0].n === 0) {
    console.log('Empty database: seeding from data/*.json');
    await seed();
  } else {
    console.log(`Schema ready; ${rows[0].n} findings already loaded`);
  }
}

main()
  .then(() => pool.end())
  .catch((err) => { console.error(err); process.exit(1); });
