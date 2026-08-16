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
const { requireCsrfHeader } = require('../middleware/csrfHeader');
const { signAccessToken } = require('../utils/jwt');
const { sha256Hex, randomToken } = require('../utils/crypto');
const { logAudit } = require('../utils/audit');
const { BadRequestError, UnauthorizedError, ConflictError } = require('../utils/errors');

const router = express.Router();

const REFRESH_COOKIE_NAME = 'lp_refresh';
const isProd = config.nodeEnv === 'production';

function refreshCookieOptions() {
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    path: '/api/auth', // scoped: only sent to auth endpoints, minimizing exposure
    maxAge: config.refreshTokenTtlDays * 24 * 60 * 60 * 1000,
  };
}

function issueRefreshToken(userId) {
  const raw = randomToken(32);
  const tokenHash = sha256Hex(raw);
  const expiresAt = new Date(Date.now() + config.refreshTokenTtlDays * 24 * 60 * 60 * 1000).toISOString();
  db.prepare(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
  ).run(userId, tokenHash, expiresAt);
  return raw;
}

function findValidRefreshToken(rawToken) {
  const tokenHash = sha256Hex(rawToken);
  const row = db.prepare(
    'SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL'
  ).get(tokenHash);
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  return row;
}

function revokeRefreshTokenRow(id) {
  db.prepare('UPDATE refresh_tokens SET revoked_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\') WHERE id = ?').run(id);
}

// ---- Register --------------------------------------------------------
router.post(
  '/register',
  requireCsrfHeader,
  authLimiter,
  [
    body('email').isEmail().withMessage('must be a valid email').normalizeEmail(),
    body('password')
      .isLength({ min: 10 })
      .withMessage('must be at least 10 characters')
      .matches(/[0-9]/)
      .withMessage('must contain a number')
      .matches(/[A-Za-z]/)
      .withMessage('must contain a letter'),
    body('fullName').trim().isLength({ min: 1, max: 200 }).withMessage('is required'),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { email, password, fullName } = req.body;

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) throw new ConflictError('An account with this email already exists');

    const passwordHash = await bcrypt.hash(password, config.bcryptCost);
    const info = db
      .prepare('INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)')
      .run(email, passwordHash, fullName, 'owner');
    db.prepare('INSERT INTO profiles (user_id) VALUES (?)').run(info.lastInsertRowid);

    logAudit({ actorUserId: info.lastInsertRowid, action: 'auth.register', ip: req.ip });

    const user = { id: info.lastInsertRowid, email, role: 'owner', tokenVersion: 0 };
    const accessToken = signAccessToken(user);
    const refreshToken = issueRefreshToken(user.id);
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, refreshCookieOptions());

    res.status(201).json({
      accessToken,
      user: { id: user.id, email, fullName, role: 'owner' },
    });
  })
);

// ---- Login -------------------------------------------------------------
router.post(
  '/login',
  requireCsrfHeader,
  authLimiter,
  [
    body('email').isEmail().withMessage('must be a valid email').normalizeEmail(),
    body('password').notEmpty().withMessage('is required'),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    // V2.0-C (docs/V2_0_C_PLAN.md §2, audit finding L4): account-level
    // lockout on top of the existing IP-based rate limiter. Checked before
    // the password comparison — an attacker with the correct password but
    // hitting a locked account still shouldn't get in until it expires.
    if (user && user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      logAudit({ actorUserId: user.id, action: 'auth.login_blocked_locked', ip: req.ip });
      throw new UnauthorizedError('This account is temporarily locked due to repeated failed login attempts. Please try again later.');
    }

    // Constant-shape response whether or not the user exists, to avoid
    // leaking account existence via timing/response differences beyond
    // what bcrypt itself already normalizes.
    const hashToCompare = user ? user.password_hash : '$2b$12$invalidsaltinvalidsaltinvalidsaltinvOK';
    const passwordMatches = await bcrypt.compare(password, hashToCompare);

    if (!user || !passwordMatches) {
      if (user) {
        const newCount = user.failed_login_count + 1;
        if (newCount >= config.accountLockoutThreshold) {
          const lockedUntil = new Date(Date.now() + config.accountLockoutMinutes * 60 * 1000).toISOString();
          db.prepare('UPDATE users SET failed_login_count = 0, locked_until = ? WHERE id = ?').run(lockedUntil, user.id);
          logAudit({ actorUserId: user.id, action: 'auth.account_locked', ip: req.ip, metadata: { threshold: config.accountLockoutThreshold } });
        } else {
          db.prepare('UPDATE users SET failed_login_count = ? WHERE id = ?').run(newCount, user.id);
        }
      }
      logAudit({ action: 'auth.login_failed', ip: req.ip, metadata: { email } });
      throw new UnauthorizedError('Invalid email or password');
    }
    if (user.status === 'disabled') {
      logAudit({ actorUserId: user.id, action: 'auth.login_blocked_disabled', ip: req.ip });
      throw new UnauthorizedError('This account has been disabled');
    }

    // Successful login resets the lockout counter.
    if (user.failed_login_count > 0 || user.locked_until) {
      db.prepare('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?').run(user.id);
    }

    logAudit({ actorUserId: user.id, action: 'auth.login_success', ip: req.ip });

    const accessToken = signAccessToken({ id: user.id, role: user.role, email: user.email, tokenVersion: user.token_version });
    const refreshToken = issueRefreshToken(user.id);
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, refreshCookieOptions());

    res.json({
      accessToken,
      user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role },
    });
  })
);

// ---- Refresh -------------------------------------------------------------
router.post(
  '/refresh',
  requireCsrfHeader,
  asyncHandler(async (req, res) => {
    const rawToken = req.cookies && req.cookies[REFRESH_COOKIE_NAME];
    if (!rawToken) throw new UnauthorizedError('No refresh token provided');

    const tokenRow = findValidRefreshToken(rawToken);
    if (!tokenRow) throw new UnauthorizedError('Refresh token is invalid or expired');

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(tokenRow.user_id);
    if (!user || user.status === 'disabled') throw new UnauthorizedError('Account unavailable');

    // Rotate: revoke the used token, issue a new one. Limits the value of
    // a stolen refresh token to a single use before detection.
    revokeRefreshTokenRow(tokenRow.id);
    const newRefreshToken = issueRefreshToken(user.id);
    res.cookie(REFRESH_COOKIE_NAME, newRefreshToken, refreshCookieOptions());

    const accessToken = signAccessToken({ id: user.id, role: user.role, email: user.email, tokenVersion: user.token_version });
    res.json({ accessToken });
  })
);

// ---- Logout -------------------------------------------------------------
router.post(
  '/logout',
  requireCsrfHeader,
  asyncHandler(async (req, res) => {
    const rawToken = req.cookies && req.cookies[REFRESH_COOKIE_NAME];
    if (rawToken) {
      const tokenRow = findValidRefreshToken(rawToken);
      if (tokenRow) {
        revokeRefreshTokenRow(tokenRow.id);
        logAudit({ actorUserId: tokenRow.user_id, action: 'auth.logout', ip: req.ip });
      }
    }
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
    res.status(204).end();
  })
);

// ---- Me -------------------------------------------------------------
router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const user = db.prepare('SELECT id, email, full_name, role, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) throw new BadRequestError('User not found');
    res.json({ user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, createdAt: user.created_at } });
  })
);

module.exports = { router, REFRESH_COOKIE_NAME, refreshCookieOptions, issueRefreshToken, findValidRefreshToken, revokeRefreshTokenRow };
