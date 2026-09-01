'use strict';

const { translatePlaceholders, resolveParams } = require('../placeholderTranslator');

describe('placeholderTranslator: basic positional translation', () => {
  test('single placeholder', () => {
    const { text, paramNames } = translatePlaceholders('SELECT * FROM users WHERE id = ?');
    expect(text).toBe('SELECT * FROM users WHERE id = $1');
    expect(paramNames).toEqual([null]);
  });

  test('multiple placeholders, numbered in order', () => {
    const { text, paramNames } = translatePlaceholders('UPDATE users SET a = ?, b = ?, c = ? WHERE id = ?');
    expect(text).toBe('UPDATE users SET a = $1, b = $2, c = $3 WHERE id = $4');
    expect(paramNames).toEqual([null, null, null, null]);
  });

  test('no placeholders at all', () => {
    const { text, paramNames } = translatePlaceholders('SELECT COUNT(*) FROM users');
    expect(text).toBe('SELECT COUNT(*) FROM users');
    expect(paramNames).toEqual([]);
  });
});

describe('placeholderTranslator: adversarial cases (the actual point of this module)', () => {
  test('a literal ? inside a single-quoted string is NOT translated', () => {
    const { text, paramNames } = translatePlaceholders("SELECT * FROM users WHERE bio = 'What is this?' AND id = ?");
    expect(text).toBe("SELECT * FROM users WHERE bio = 'What is this?' AND id = $1");
    expect(paramNames).toEqual([null]);
  });

  test('multiple literal ? characters inside a string are all preserved, only the real placeholder is translated', () => {
    const { text } = translatePlaceholders("INSERT INTO x (msg) VALUES ('??? really?') RETURNING id");
    expect(text).toBe("INSERT INTO x (msg) VALUES ('??? really?') RETURNING id");
  });

  test('an escaped single quote inside a string literal does not break state tracking', () => {
    const { text, paramNames } = translatePlaceholders("SELECT * FROM x WHERE note = 'It''s a test?' AND id = ?");
    expect(text).toBe("SELECT * FROM x WHERE note = 'It''s a test?' AND id = $1");
    expect(paramNames).toEqual([null]);
  });

  test('a ? inside a double-quoted identifier is not translated', () => {
    const { text, paramNames } = translatePlaceholders('SELECT "weird?column" FROM x WHERE id = ?');
    expect(text).toBe('SELECT "weird?column" FROM x WHERE id = $1');
    expect(paramNames).toEqual([null]);
  });

  test('a ? inside a line comment is not translated', () => {
    const sql = 'SELECT * FROM x -- is this a placeholder? no.\nWHERE id = ?';
    const { text, paramNames } = translatePlaceholders(sql);
    expect(text).toBe('SELECT * FROM x -- is this a placeholder? no.\nWHERE id = $1');
    expect(paramNames).toEqual([null]);
  });

  test('a ? inside a block comment is not translated', () => {
    const sql = 'SELECT * FROM x /* placeholder? not here */ WHERE id = ?';
    const { text, paramNames } = translatePlaceholders(sql);
    expect(text).toBe('SELECT * FROM x /* placeholder? not here */ WHERE id = $1');
    expect(paramNames).toEqual([null]);
  });

  test('a multi-line block comment containing ? is not translated', () => {
    const sql = 'SELECT * FROM x /* line one\nline two with a ? mark\nline three */ WHERE id = ?';
    const { text, paramNames } = translatePlaceholders(sql);
    expect(text).toContain('line two with a ? mark');
    expect(text.endsWith('WHERE id = $1')).toBe(true);
    expect(paramNames).toEqual([null]);
  });

  test('combination: string, comment, and real placeholders all in one statement', () => {
    const sql = "-- find a user?\nSELECT * FROM users /* is active? */ WHERE bio != 'none?' AND status = ? AND role = ?";
    const { text, paramNames } = translatePlaceholders(sql);
    expect(text).toBe("-- find a user?\nSELECT * FROM users /* is active? */ WHERE bio != 'none?' AND status = $1 AND role = $2");
    expect(paramNames).toEqual([null, null]);
  });
});

describe('placeholderTranslator: named @param translation (utils/audit.js style)', () => {
  test('translates @name tokens to $n in order of first appearance', () => {
    const sql = 'INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, ip_address, metadata_json) ' +
      'VALUES (@actor_user_id, @action, @target_type, @target_id, @ip_address, @metadata_json)';
    const { text, paramNames } = translatePlaceholders(sql);
    expect(text).toBe(
      'INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, ip_address, metadata_json) ' +
      'VALUES ($1, $2, $3, $4, $5, $6)'
    );
    expect(paramNames).toEqual(['actor_user_id', 'action', 'target_type', 'target_id', 'ip_address', 'metadata_json']);
  });

  test('an email address containing @ inside a string literal is NOT touched', () => {
    const { text } = translatePlaceholders("SELECT * FROM x WHERE email = 'someone@example.com' AND id = @id");
    expect(text).toBe("SELECT * FROM x WHERE email = 'someone@example.com' AND id = $1");
  });

  test('mixing ? and @name in the same statement throws rather than silently mis-translating', () => {
    expect(() => translatePlaceholders('SELECT * FROM x WHERE a = ? AND b = @name')).toThrow(/mixes positional/);
  });
});

describe('resolveParams: positional style', () => {
  test('spreads positional args in order, unchanged', () => {
    const paramNames = [null, null, null];
    expect(resolveParams(paramNames, [1, 'two', 3])).toEqual([1, 'two', 3]);
  });

  test('a single array argument is passed through as-is (defensive support)', () => {
    const paramNames = [null, null];
    expect(resolveParams(paramNames, [[1, 2]])).toEqual([1, 2]);
  });

  test('no params', () => {
    expect(resolveParams([], [])).toEqual([]);
  });
});

describe('resolveParams: named style', () => {
  test('extracts values from the object argument in placeholder-appearance order', () => {
    const paramNames = ['actor_user_id', 'action', 'target_type'];
    const result = resolveParams(paramNames, [{ actor_user_id: 5, action: 'x.y', target_type: 'user', target_id: 99 }]);
    expect(result).toEqual([5, 'x.y', 'user']);
  });

  test('throws clearly if a required named parameter is missing (does not silently send undefined)', () => {
    const paramNames = ['actor_user_id', 'action'];
    expect(() => resolveParams(paramNames, [{ actor_user_id: 5 }])).toThrow(/Missing named parameter '@action'/);
  });

  test('a null value for a present key is passed through correctly (not treated as missing)', () => {
    const paramNames = ['target_type', 'target_id'];
    const result = resolveParams(paramNames, [{ target_type: null, target_id: null }]);
    expect(result).toEqual([null, null]);
  });
});
