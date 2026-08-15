// Applies the base schema and then numbered forward migrations.
'use strict';
const fs = require('fs'); const path = require('path'); const db = require('./index');
const schema = fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8');
db.exec(schema);
const migrationsDir = path.join(__dirname,'migrations');
if (fs.existsSync(migrationsDir)) {
  for (const name of fs.readdirSync(migrationsDir).filter(n=>/^\d+_.+\.sql$/.test(n)).sort()) {
    if (db.prepare('SELECT 1 FROM schema_migrations WHERE name = ?').get(name)) continue;
    const sql=fs.readFileSync(path.join(migrationsDir,name),'utf8');
    const apply=db.transaction(()=>{ db.exec(sql); db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run(name); });
    try { apply(); } catch (err) {
      // The base schema may already contain a column introduced by a later
      // migration (fresh clones). Treat that specific SQLite duplicate-column
      // case as already applied; all other migration errors are fatal.
      if (/duplicate column name/i.test(String(err.message))) db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run(name);
      else throw err;
    }
  }
}
if (!db.prepare('SELECT 1 FROM schema_migrations WHERE name = ?').get('initial_schema')) db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run('initial_schema');
console.log(`[migrate] schema and migrations applied to ${db.name}`);
