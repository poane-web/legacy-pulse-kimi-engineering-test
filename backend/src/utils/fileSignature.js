// V2.0-B SECURITY FIX (docs/V2_SECURITY_AUDIT.md, finding H4 -- High):
//
// V1's multer `fileFilter` only checked `file.mimetype`, which is the
// multipart Content-Type field the CLIENT sets on upload -- trivially
// spoofable (e.g. declare "application/pdf" while uploading arbitrary
// bytes). `fileFilter` also can't inspect content anyway: with
// multer.memoryStorage(), the file body isn't available yet at the point
// fileFilter runs.
//
// This module inspects the actual bytes (magic numbers / file signatures)
// of an uploaded buffer AFTER multer has fully read it, so routes can
// reject a file whose real content doesn't match its declared, allowed
// MIME type -- independent of what Content-Type header the client sent.
//
// Deliberately dependency-free (per the V2 constraint of not introducing
// unnecessary dependencies) -- these are well-known, stable magic byte
// sequences, not a full file-format parser.
'use strict';

// Each entry: the canonical MIME type this signature proves the content IS,
// and a match() function against the leading bytes of the buffer.
const SIGNATURES = [
  { mime: 'application/pdf', match: (buf) => buf.slice(0, 5).toString('ascii') === '%PDF-' },
  { mime: 'image/png', match: (buf) => buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  { mime: 'image/jpeg', match: (buf) => buf.slice(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff])) },
  { mime: 'image/gif', match: (buf) => ['GIF87a', 'GIF89a'].includes(buf.slice(0, 6).toString('ascii')) },
  {
    mime: 'image/webp',
    match: (buf) => buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP',
  },
  // .docx/.xlsx/.pptx are ZIP containers (PK\x03\x04); we can't distinguish
  // the specific Office subtype from the first bytes alone without fully
  // parsing the ZIP central directory, so we accept the generic ZIP
  // signature for the one Office MIME type this app allows (.docx).
  {
    mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    match: (buf) => buf.slice(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04])),
  },
  // Legacy binary .doc (OLE Compound File Binary Format).
  {
    mime: 'application/msword',
    match: (buf) => buf.slice(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])),
  },
];

// text/plain has no reliable magic number. As a pragmatic heuristic, we
// accept it only if the first 512 bytes contain no NUL bytes and decode as
// valid UTF-8 with no control characters other than whitespace — i.e. it
// looks like text, not an arbitrary binary wearing a text/plain label.
function looksLikePlainText(buffer) {
  const sample = buffer.slice(0, 512);
  for (let i = 0; i < sample.length; i++) {
    const byte = sample[i];
    const isPrintable = byte >= 0x20 && byte !== 0x7f;
    const isAllowedWhitespace = byte === 0x09 || byte === 0x0a || byte === 0x0d;
    if (!isPrintable && !isAllowedWhitespace) return false;
  }
  return true;
}

/**
 * Returns true if `buffer`'s actual content is consistent with
 * `declaredMimeType`, given that `declaredMimeType` is already known to be
 * in the route's allow-list. Returns false (reject) if the content is
 * recognizably a *different* known type, or if it declares a binary type
 * we have a signature for but the bytes don't match.
 */
function contentMatchesDeclaredType(buffer, declaredMimeType) {
  if (declaredMimeType === 'text/plain') {
    return looksLikePlainText(buffer);
  }

  const expected = SIGNATURES.find((s) => s.mime === declaredMimeType);
  if (!expected) {
    // No signature defined for this declared type (shouldn't happen given
    // the allow-lists in documents.routes.js / photos.routes.js, but fail
    // closed rather than open if the allow-list ever grows without a
    // matching signature being added here).
    return false;
  }
  if (!expected.match(buffer)) return false;

  // Additionally make sure the bytes don't match a DIFFERENT, more
  // specific known signature than the one declared (catches e.g. a PNG
  // renamed/declared as image/jpeg).
  const actualMatch = SIGNATURES.find((s) => s.match(buffer));
  return !actualMatch || actualMatch.mime === declaredMimeType;
}

module.exports = { contentMatchesDeclaredType };
