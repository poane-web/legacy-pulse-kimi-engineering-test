'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const { body } = require('express-validator');
const db = require('../db');
const config = require('../config/env');
const asyncHandler = require('../utils/asyncHandler');
const { handleValidation } = require('../middleware/validate');
const { authLimiter } = require('../middleware/rateLimit');
const { requireAuth } = require('../middleware/auth');
const { signAccessToken } = require('../utils/jwt');
const { sha256Hex, randomToken } = require('../utils/crypto');
const { logAudit } = require('../utils/audit');
const { BadRequestError, UnauthorizedError, ConflictError } = require('../utils/errors');

const router = express.Router();
const REFRESH_COOKIE_NAME = 'lp_refresh';
const isProd = config.nodeEnv === 'production';
const SAME_SITE_HEADER = 'x-legacy-pulse-request';

function requireSameSiteRequest(req, res, next) {
  if (req.get(SAME_SITE_HEADER) !== '1') return next(new UnauthorizedError('Missing request integrity header'));
  return next();
}

function refreshCookieOptions() {
  return { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/api/auth', maxAge: config.refreshTokenTtlDays * 24 * 60 * 60 * 1000 };
}
function issueRefreshToken(userId) {
  const raw = randomToken(32);
  const tokenHash = sha256Hex(raw);
  const expiresAt = new Date(Date.now() + config.refreshTokenTtlDays * 86400000).toISOString();
  db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)').run(userId, tokenHash, expiresAt);
  return raw;
}
function findValidRefreshToken(rawToken) {
  if (!rawToken || typeof rawToken !== 'string') return null;
  const tokenHash = sha256Hex(rawToken);
  const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL').get(tokenHash);
  if (!row || new Date(row.expires_at).getTime() < Date.now()) return null;
  return row;
}
function revokeRefreshTokenRow(id) {
  db.prepare("UPDATE refresh_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ? AND revoked_at IS NULL").run(id);
}

router.post('/register', authLimiter, [body('email').isEmail().normalizeEmail(), body('password').isLength({ min: 10 }).matches(/[0-9]/).matches(/[A-Za-z]/), body('fullName').trim().isLength({ min: 1, max: 200 })], handleValidation,
  asyncHandler(async (req, res) => {
    const { email, password, fullName } = req.body;
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) throw new ConflictError('An account with this email already exists');
    const passwordHash = await bcrypt.hash(password, config.bcryptCost);
    const info = db.prepare('INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)').run(email, passwordHash, fullName, 'owner');
    db.prepare('INSERT INTO profiles (user_id) VALUES (?)').run(info.lastInsertRowid);
    logAudit({ actorUserId: info.lastInsertRowid, action: 'auth.register', ip: req.ip });
    const user = { id: info.lastInsertRowid, email, role: 'owner' };
    const accessToken = signAccessToken(user);
    res.cookie(REFRESH_COOKIE_NAME, issueRefreshToken(user.id), refreshCookieOptions());
    res.status(201).json({ accessToken, user: { id: user.id, email, fullName, role: 'owner' } });
  }));

router.post('/login', authLimiter, [body('email').isEmail().normalizeEmail(), body('password').notEmpty()], handleValidation,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    const hashToCompare = user ? user.password_hash : '$2b$12$invalidsaltinvalidsaltinvalidsaltinvOK';
    const passwordMatches = await bcrypt.compare(password, hashToCompare);
    if (!user || !passwordMatches) { logAudit({ action: 'auth.login_failed', ip: req.ip, metadata: { email } }); throw new UnauthorizedError('Invalid email or password'); }
    if (user.status === 'disabled') throw new UnauthorizedError('This account has been disabled');
    logAudit({ actorUserId: user.id, action: 'auth.login_success', ip: req.ip });
    res.cookie(REFRESH_COOKIE_NAME, issueRefreshToken(user.id), refreshCookieOptions());
    res.json({ accessToken: signAccessToken(user), user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role } });
  }));

router.post('/refresh', requireSameSiteRequest, asyncHandler(async (req, res) => {
  const rawToken = req.cookies && req.cookies[REFRESH_COOKIE_NAME];
  const tokenRow = findValidRefreshToken(rawToken);
  if (!tokenRow) throw new UnauthorizedError('Refresh token is invalid or expired');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(tokenRow.user_id);
  if (!user || user.status === 'disabled') throw new UnauthorizedError('Account unavailable');
  // SQLite serializes the transaction. Re-check the token inside it so two
  // concurrent refresh requests cannot both consume the same token.
  const rotate = db.transaction(() => {
    const current = db.prepare('SELECT * FROM refresh_tokens WHERE id = ? AND revoked_at IS NULL').get(tokenRow.id);
    if (!current || new Date(current.expires_at).getTime() < Date.now()) throw new UnauthorizedError('Refresh token is invalid or expired');
    revokeRefreshTokenRow(current.id);
    return issueRefreshToken(user.id);
  });
  const newRefreshToken = rotate();
  res.cookie(REFRESH_COOKIE_NAME, newRefreshToken, refreshCookieOptions());
  res.json({ accessToken: signAccessToken(user) });
}));

router.post('/logout', requireSameSiteRequest, asyncHandler(async (req, res) => {
  const rawToken = req.cookies && req.cookies[REFRESH_COOKIE_NAME];
  if (rawToken) {
    const tokenRow = findValidRefreshToken(rawToken);
    if (tokenRow) { revokeRefreshTokenRow(tokenRow.id); logAudit({ actorUserId: tokenRow.user_id, action: 'auth.logout', ip: req.ip }); }
  }
  res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
  res.status(204).end();
}));

router.get('/me', requireAuth, asyncHandler(async (req, res) => {
  const user = db.prepare('SELECT id, email, full_name, role, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) throw new BadRequestError('User not found');
  res.json({ user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, createdAt: user.created_at } });
}));

module.exports = { router, REFRESH_COOKIE_NAME, refreshCookieOptions, issueRefreshToken, findValidRefreshToken, revokeRefreshTokenRow };
