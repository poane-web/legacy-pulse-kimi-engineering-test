// Single database connection module. All data access in the app goes
// through `db` exported from here — no route/service file opens its own
// connection. This is the seam that would need to change (to a Postgres
// pool, for example) to move off SQLite; nothing else would.
'use strict';

const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const config = require('../config/env');

const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(config.dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

module.exports = db;
