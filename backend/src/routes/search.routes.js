// Search across an owner's own content.
//
// Implementation note (documented limitation): because memory/story/
// instruction content and document descriptions are encrypted at rest with
// random IVs, they cannot be searched with a SQL LIKE query against
// ciphertext. For the MVP we decrypt the (small, per-user-bounded) set of
// candidate rows in memory and match server-side. This is fine at MVP
// scale (a single user's own records) but does NOT scale to searching
// across large datasets — a production system would use per-user
// client-side search, a searchable-encryption scheme, or an encrypted
// search index. Titles/filenames/tags/event titles/categories are not
// encrypted (see docs/DATABASE.md) and are searched directly in SQL.
'use strict';

const express = require('express');
const { query } = require('express-validator');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');
const { decryptField } = require('../utils/crypto');

const router = express.Router();
router.use(requireAuth);

router.get(
  '/',
  [query('q').trim().isLength({ min: 1, max: 200 })],
  handleValidation,
  asyncHandler(async (req, res) => {
    const q = req.query.q.toLowerCase();
    const results = [];

    const memories = db.prepare('SELECT * FROM memories WHERE owner_id = ?').all(req.user.id);
    for (const m of memories) {
      const content = decryptField(m.content_encrypted);
      if (m.title.toLowerCase().includes(q) || (m.tags || '').toLowerCase().includes(q) || content.toLowerCase().includes(q)) {
        results.push({ type: m.type, id: m.id, title: m.title, snippet: content.slice(0, 160) });
      }
    }

    const events = db.prepare('SELECT * FROM life_events WHERE owner_id = ?').all(req.user.id);
    for (const e of events) {
      if (e.title.toLowerCase().includes(q) || (e.category || '').toLowerCase().includes(q)) {
        results.push({ type: 'life_event', id: e.id, title: e.title, snippet: e.event_date });
      }
    }

    const documents = db.prepare('SELECT * FROM documents WHERE owner_id = ?').all(req.user.id);
    for (const d of documents) {
      const filename = decryptField(d.original_filename_encrypted);
      if (filename.toLowerCase().includes(q)) {
        results.push({ type: 'document', id: d.id, title: filename, snippet: d.mime_type });
      }
    }

    const beneficiaries = db.prepare('SELECT * FROM beneficiaries WHERE owner_id = ?').all(req.user.id);
    for (const b of beneficiaries) {
      if (b.full_name.toLowerCase().includes(q) || (b.relationship || '').toLowerCase().includes(q)) {
        results.push({ type: 'beneficiary', id: b.id, title: b.full_name, snippet: b.relationship || '' });
      }
    }

    res.json({ query: req.query.q, results });
  })
);

module.exports = router;
