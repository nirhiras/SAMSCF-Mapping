-- ForeScout findings schema. Safe to run repeatedly.

CREATE TABLE IF NOT EXISTS imports (
  id          SERIAL PRIMARY KEY,
  source      TEXT NOT NULL,
  imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS summary_metrics (
  metric TEXT PRIMARY KEY,
  label  TEXT NOT NULL,
  value  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id         TEXT PRIMARY KEY,
  pillar     TEXT NOT NULL,
  finding    TEXT NOT NULL,
  affected   INTEGER NOT NULL DEFAULT 0,
  unverified INTEGER NOT NULL DEFAULT 0,
  severity   TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
  priority   SMALLINT NOT NULL,
  next_step  TEXT NOT NULL,
  -- Remediation tracking, edited from the web page. Seeding never overwrites these.
  status     TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'In progress', 'Done', 'Accepted risk')),
  owner      TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS control_coverage (
  id      TEXT PRIMARY KEY,
  area    TEXT NOT NULL,
  control TEXT NOT NULL,
  covered INTEGER NOT NULL,
  total   INTEGER NOT NULL,
  note    TEXT
);

CREATE TABLE IF NOT EXISTS device_mix (
  type  TEXT PRIMARY KEY,
  hosts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS legacy_hosts (
  id       TEXT PRIMARY KEY,
  host     TEXT NOT NULL,
  ip       TEXT,
  function TEXT,
  os       TEXT,
  segment  TEXT,
  purdue   TEXT
);
