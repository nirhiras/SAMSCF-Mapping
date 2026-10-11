const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. On Railway, add a reference to the Postgres service variable DATABASE_URL.');
  process.exit(1);
}

// Railway's public Postgres proxy needs TLS; its private network and local databases don't.
const url = process.env.DATABASE_URL;
const needsSsl = process.env.PGSSL === 'true' || /proxy\.rlwy\.net|railway\.app/.test(url);

const pool = new Pool({
  connectionString: url,
  ssl: needsSsl ? { rejectUnauthorized: false } : false,
});

module.exports = { pool };
