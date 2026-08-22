// V3 (docs/security/V3-THREAT-MODEL.md, finding V3-L1): defense-in-depth
// sanitization for filenames placed into the Content-Disposition response
// header. Node's http module already rejects raw CR/LF in header values
// at the runtime level (preventing classic HTTP response-splitting via
// setHeader), so this is not closing an exploitable gap in this specific
// Node version -- it's removing reliance on that runtime behavior being
// present, and stripping other control characters and excessive length
// that could confuse HTTP clients or downstream proxies/CDNs even without
// enabling header injection outright.
'use strict';

function sanitizeFilenameForHeader(filename) {
  if (!filename) return 'download';
  // Strip all C0/C1 control characters (including CR/LF) and double quotes.
  // eslint-disable-next-line no-control-regex
  const stripped = String(filename).replace(/[\x00-\x1f\x7f-\x9f"]/g, '');
  const trimmed = stripped.trim();
  const limited = trimmed.slice(0, 200); // avoid unreasonably long header values
  return limited.length > 0 ? limited : 'download';
}

module.exports = { sanitizeFilenameForHeader };
