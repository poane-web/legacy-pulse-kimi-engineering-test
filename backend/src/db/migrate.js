// Migration runner.
//
// V1 applied schema.sql only (idempotent via CREATE TABLE IF NOT EXISTS)
// and recorded a single 'initial_schema' marker. V2 keeps that as the
// baseline for brand-new databases, and adds a real incremental-migration
// mechanism (backend/src/db/migrations/*.js, applied in filename order,
// each recorded individually in schema_migrations) for schema changes that
// need to safely evolve an *existing* database -- such as adding a column
// with a backfilled default, which CREATE TABLE IF NOT EXISTS cannot do.
//
// Both fresh installs and existing V1 databases end up in the same final
// state: schema.sql is applied first (a no-op for already-existing
// tables/columns), then any migration whose name isn't yet in
// schema_migrations is applied and recorded.
'use strict';

const fs = require('fs');
const path = require('path');
const db = require('./index');

const schemaPath = path.join(__dirname, 'schema.sql');
const schema = fs.readFileSync(schemaPath, 'utf8');
db.exec(schema);

const already = db.prepare('SELECT 1 FROM schema_migrations WHERE name = ?').get('initial_schema');
if (!already) {
  db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run('initial_schema');
}

const migrationsDir = path.join(__dirname, 'migrations');
const migrationFiles = fs.existsSync(migrationsDir)
  ? fs.readdirSync(migrationsDir).filter((f) => f.endsWith('.js')).sort()
  : [];

for (const file of migrationFiles) {
  const migration = require(path.join(migrationsDir, file));
  const applied = db.prepare('SELECT 1 FROM schema_migrations WHERE name = ?').get(migration.name);
  if (applied) continue;

  const run = db.transaction(() => {
    migration.up(db);
    db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run(migration.name);
  });
  run();
  console.log(`[migrate] applied ${migration.name}`);
}

console.log(`[migrate] schema up to date at ${db.name}`);
