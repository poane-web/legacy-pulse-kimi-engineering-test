'use strict';

function hasPrefix(buffer, hex) {
  const sig = Buffer.from(hex, 'hex');
  return buffer.length >= sig.length && buffer.subarray(0, sig.length).equals(sig);
}

function isPng(b) { return hasPrefix(b, '89504e470d0a1a0a'); }
function isJpeg(b) { return hasPrefix(b, 'ffd8ff'); }
function isPdf(b) { return hasPrefix(b, '255044462d'); }
function isZip(b) { return hasPrefix(b, '504b0304') || hasPrefix(b, '504b0506') || hasPrefix(b, '504b0708'); }
function isOle(b) { return hasPrefix(b, 'd0cf11e0a1b11ae1'); }

function matchesDeclaredMime(buffer, mime) {
  if (!Buffer.isBuffer(buffer)) return false;
  switch (mime) {
    case 'image/png': return isPng(buffer);
    case 'image/jpeg': return isJpeg(buffer);
    case 'application/pdf': return isPdf(buffer);
    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': return isZip(buffer);
    case 'application/msword': return isOle(buffer);
    case 'text/plain': {
      // Text is inherently less self-describing. Reject NUL bytes and invalid
      // UTF-8 rather than trusting the multipart MIME header alone.
      if (buffer.includes(0)) return false;
      try { new TextDecoder('utf-8', { fatal: true }).decode(buffer); return true; } catch { return false; }
    }
    default: return false;
  }
}

module.exports = { matchesDeclaredMime };
