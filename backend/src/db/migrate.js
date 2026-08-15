// Applies schema.sql (idempotent: uses CREATE TABLE IF NOT EXISTS) and
// records a migration marker. In a larger system this would iterate over
// numbered files in ./migrations; schema.sql is intentionally the single
// source of truth for this MVP's schema, documented in docs/DATABASE.md.
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

console.log(`[migrate] schema applied to ${db.name}`);
