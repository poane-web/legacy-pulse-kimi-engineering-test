// PostgreSQL adapter Step 1: placeholder translation.
//
// The application's SQL is written in better-sqlite3's dialect:
//   - positional `?` placeholders (the overwhelming majority of call sites)
//   - ONE file (utils/audit.js) uses named `@paramName` placeholders bound
//     from an object argument to `.run({...})`
//
// PostgreSQL (via `pg`) only understands `$1, $2, $3, ...` positional
// placeholders. This module translates SQLite-dialect SQL to
// Postgres-dialect SQL.
//
// CRITICAL CORRECTNESS REQUIREMENT (explicitly required, not optional):
// this must NOT be a naive `sql.replace(/\?/g, ...)` — a `?` or `@word`
// appearing inside a single-quoted string literal, a double-quoted
// identifier, a line comment (`-- ...`), or a block comment (`/* ... */`)
// is not a placeholder and must be left untouched. This module is a real
// (small) SQL tokenizer that tracks lexical context character-by-character
// and only treats `?`/`@word` as a placeholder when outside all of those
// contexts. See db/postgres/__tests__/placeholderTranslator.test.js for
// the specific adversarial cases this guards against (a literal '?' inside
// a quoted string, inside a comment, escaped quotes, etc).
'use strict';

const STATE = {
  NORMAL: 'NORMAL',
  SINGLE_QUOTE: 'SINGLE_QUOTE',
  DOUBLE_QUOTE: 'DOUBLE_QUOTE',
  LINE_COMMENT: 'LINE_COMMENT',
  BLOCK_COMMENT: 'BLOCK_COMMENT',
};

/**
 * Translates SQLite-dialect SQL (positional `?` and/or named `@word`
 * placeholders) into PostgreSQL-dialect SQL (`$1, $2, ...`).
 *
 * @param {string} sql
 * @returns {{ text: string, paramNames: (string|null)[] }}
 *   `text` is the translated SQL. `paramNames` has one entry per
 *   placeholder found, in order: `null` for a positional `?` placeholder,
 *   or the parameter name (without the leading `@`) for a named
 *   placeholder. A SQL string mixing `?` and `@name` styles is not valid
 *   in this codebase (and isn't produced by better-sqlite3 either) and
 *   will throw.
 */
function translatePlaceholders(sql) {
  let state = STATE.NORMAL;
  let out = '';
  let paramIndex = 0;
  const paramNames = [];
  let sawPositional = false;
  let sawNamed = false;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (state === STATE.SINGLE_QUOTE) {
      out += ch;
      if (ch === "'") {
        if (next === "'") {
          out += next;
          i++;
        } else {
          state = STATE.NORMAL;
        }
      }
      continue;
    }

    if (state === STATE.DOUBLE_QUOTE) {
      out += ch;
      if (ch === '"') state = STATE.NORMAL;
      continue;
    }

    if (state === STATE.LINE_COMMENT) {
      out += ch;
      if (ch === '\n') state = STATE.NORMAL;
      continue;
    }

    if (state === STATE.BLOCK_COMMENT) {
      out += ch;
      if (ch === '*' && next === '/') {
        out += next;
        i++;
        state = STATE.NORMAL;
      }
      continue;
    }

    // state === NORMAL
    if (ch === "'") {
      state = STATE.SINGLE_QUOTE;
      out += ch;
      continue;
    }
    if (ch === '"') {
      state = STATE.DOUBLE_QUOTE;
      out += ch;
      continue;
    }
    if (ch === '-' && next === '-') {
      state = STATE.LINE_COMMENT;
      out += ch;
      continue;
    }
    if (ch === '/' && next === '*') {
      state = STATE.BLOCK_COMMENT;
      out += ch;
      continue;
    }

    if (ch === '?') {
      sawPositional = true;
      paramIndex += 1;
      paramNames.push(null);
      out += `$${paramIndex}`;
      continue;
    }

    if (ch === '@' && /[A-Za-z_]/.test(next || '')) {
      sawNamed = true;
      let j = i + 1;
      let name = '';
      while (j < sql.length && /[A-Za-z0-9_]/.test(sql[j])) {
        name += sql[j];
        j++;
      }
      paramIndex += 1;
      paramNames.push(name);
      out += `$${paramIndex}`;
      i = j - 1;
      continue;
    }

    out += ch;
  }

  if (sawPositional && sawNamed) {
    throw new Error('SQL mixes positional (?) and named (@name) placeholders -- not supported: ' + sql);
  }

  return { text: out, paramNames };
}

/**
 * Given the paramNames produced by translatePlaceholders and the
 * arguments actually passed to .get()/.all()/.run(), produces the
 * correctly-ordered flat array `pg` expects.
 *
 * Two calling conventions must be supported, matching better-sqlite3:
 *   - positional: db.prepare('...WHERE id=? AND x=?').get(1, 2)
 *   - named:      db.prepare('...VALUES(@a,@b)').run({ a: 1, b: 2 })
 */
function resolveParams(paramNames, args) {
  const isNamedStatement = paramNames.some((n) => n !== null);
  if (!isNamedStatement) {
    if (args.length === 1 && Array.isArray(args[0])) return args[0];
    return args;
  }
  const obj = args[0] || {};
  return paramNames.map((name) => {
    if (!(name in obj)) {
      throw new Error(`Missing named parameter '@${name}' for prepared statement`);
    }
    return obj[name];
  });
}

module.exports = { translatePlaceholders, resolveParams };
