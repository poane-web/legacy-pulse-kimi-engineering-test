// Central API client. Every network call in the app goes through here so
// the access-token-refresh-on-401 logic lives in exactly one place.
//
// Security note: the access token is kept ONLY in memory (a module-level
// variable), never in localStorage/sessionStorage. That limits what an XSS
// payload could steal to whatever's currently in memory for this page
// load, rather than a persistent token an attacker could exfiltrate and
// reuse later. The refresh token never touches JS at all — it lives in an
// httpOnly cookie set by the server (see backend/src/routes/auth.routes.js).
'use strict';

const API_BASE = '/api';

let accessToken = null;
let onUnauthorized = () => {};

export function setAccessToken(token) {
  accessToken = token;
}
export function getAccessToken() {
  return accessToken;
}
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

let refreshPromise = null;
async function refreshAccessToken() {
  if (!refreshPromise) {
    refreshPromise = fetch(`${API_BASE}/auth/refresh`, { method: 'POST', credentials: 'include', headers: { 'X-Legacy-Pulse-Client': '1' } })
      .then(async (res) => {
        if (!res.ok) throw new Error('refresh_failed');
        const data = await res.json();
        setAccessToken(data.accessToken);
        return data.accessToken;
      })
      .finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

/**
 * @param {string} path - e.g. '/memories'
 * @param {object} [opts]
 * @param {string} [opts.method]
 * @param {object} [opts.body] - JSON body (do not use alongside formData)
 * @param {FormData} [opts.formData] - for file uploads
 * @param {boolean} [opts.skipAuth] - for public endpoints (login/register)
 * @param {boolean} [opts.raw] - return the raw Response (for file downloads)
 */
export async function apiRequest(path, opts = {}) {
  const { method = 'GET', body, formData, skipAuth = false, raw = false } = opts;

  async function doFetch(token) {
    const headers = {};
    if (!formData) headers['Content-Type'] = 'application/json';
    if (token) headers['Authorization'] = `Bearer ${token}`;
    // Required by the backend's CSRF defense-in-depth on cookie-authenticated
    // auth endpoints (see backend/src/middleware/csrfHeader.js) — a
    // cross-site <form> submission cannot set custom headers, so this
    // proves the request came from our own JavaScript. Harmless to send on
    // every request, not just /auth/*.
    headers['X-Legacy-Pulse-Client'] = '1';

    return fetch(`${API_BASE}${path}`, {
      method,
      headers,
      credentials: 'include',
      body: formData ? formData : body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  let res = await doFetch(skipAuth ? null : accessToken);

  // Transparent silent refresh on 401 (except for the auth endpoints
  // themselves, to avoid infinite loops).
  if (res.status === 401 && !skipAuth && !path.startsWith('/auth/')) {
    try {
      const newToken = await refreshAccessToken();
      res = await doFetch(newToken);
    } catch (e) {
      onUnauthorized();
      throw new ApiError('Session expired. Please log in again.', 401);
    }
  }

  if (raw) return res;

  let data = null;
  try { data = await res.json(); } catch (e) { /* no JSON body, e.g. 204 */ }

  if (!res.ok) {
    const message = (data && data.error && data.error.message) || `Request failed (${res.status})`;
    if (res.status === 401 && !skipAuth) onUnauthorized();
    throw new ApiError(message, res.status, data && data.error && data.error.code);
  }
  return data;
}

export class ApiError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
