// V2.0-C (docs/V2_0_C_PLAN.md §1): a single, consistent way to build the
// AAD context string used across every route that encrypts/decrypts
// owner-scoped content, so the same context is guaranteed to be produced
// at both encrypt and decrypt time without each route inventing its own
// format (a mismatch here would manifest as legitimate data becoming
// undecryptable, so consistency matters more than the exact format).
'use strict';

function ownerContext(table, column, ownerId) {
  return `${table}.${column}:owner:${ownerId}`;
}

module.exports = { ownerContext };
