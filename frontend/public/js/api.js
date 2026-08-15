// Central API client. Access tokens stay in memory; refresh tokens stay in
// an httpOnly cookie. All cookie-only authentication calls also carry a
// non-simple request header as CSRF defense-in-depth.
'use strict';

const API_BASE = '/api';
const REQUEST_INTEGRITY_HEADER = 'X-Legacy-Pulse-Request';
let accessToken = null;
let onUnauthorized = () => {};

export function setAccessToken(token) { accessToken = token; }
export function getAccessToken() { return accessToken; }
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

let refreshPromise = null;
async function refreshAccessToken() {
  if (!refreshPromise) {
    refreshPromise = fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST', credentials: 'include', headers: { [REQUEST_INTEGRITY_HEADER]: '1' },
    }).then(async (res) => {
      if (!res.ok) throw new Error('refresh_failed');
      const data = await res.json(); setAccessToken(data.accessToken); return data.accessToken;
    }).finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

export async function apiRequest(path, opts = {}) {
  const { method = 'GET', body, formData, skipAuth = false, raw = false } = opts;
  async function doFetch(token) {
    const headers = { [REQUEST_INTEGRITY_HEADER]: '1' };
    if (!formData) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    return fetch(`${API_BASE}${path}`, { method, headers, credentials: 'include', body: formData ? formData : body !== undefined ? JSON.stringify(body) : undefined });
  }
  let res = await doFetch(skipAuth ? null : accessToken);
  if (res.status === 401 && !skipAuth && !path.startsWith('/auth/')) {
    try { res = await doFetch(await refreshAccessToken()); }
    catch (e) { onUnauthorized(); throw new ApiError('Session expired. Please log in again.', 401); }
  }
  if (raw) return res;
  let data = null; try { data = await res.json(); } catch (e) { /* 204 */ }
  if (!res.ok) {
    const message = (data && data.error && data.error.message) || `Request failed (${res.status})`;
    if (res.status === 401 && !skipAuth) onUnauthorized();
    throw new ApiError(message, res.status, data && data.error && data.error.code);
  }
  return data;
}

export class ApiError extends Error {
  constructor(message, status, code) { super(message); this.status = status; this.code = code; }
}
