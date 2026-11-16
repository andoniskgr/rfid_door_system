'use strict';

const crypto = require('crypto');
const argon2 = require('argon2');
const { Secret, TOTP } = require('otpauth');
const dbApi = require('./db');

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest();
}

function sameString(a, b) {
  return crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function issueSetupToken(db, nowSec, ttlSec) {
  const token = crypto.randomBytes(32).toString('hex');
  dbApi.saveSetupToken(db, tokenHash(token), nowSec + ttlSec);
  return token;
}

function setupTokenValid(db, token, nowSec) {
  const row = dbApi.getSetupToken(db);
  if (!row || row.expires_at < nowSec) return false;
  const presented = sha256(String(token || ''));
  const stored = Buffer.from(row.token_hash, 'hex');
  if (stored.length !== presented.length) return false;
  return crypto.timingSafeEqual(stored, presented);
}

function argonOptions(config) {
  return { type: argon2.argon2id, ...config.argon };
}

async function hashPassword(password, config) {
  return argon2.hash(password, argonOptions(config));
}

function newTotp(username) {
  const secret = new Secret({ size: 20 });
  const totp = new TOTP({
    issuer: 'Door access',
    label: username,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret,
  });
  return { base32: secret.base32, uri: totp.toString() };
}

function totpForSecret(base32, username) {
  return new TOTP({
    issuer: 'Door access',
    label: username || 'admin',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(base32),
  });
}

function verifyTotp(base32, token, username) {
  const code = String(token || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(code)) return false;
  try {
    return totpForSecret(base32, username).validate({ token: code, window: 1 }) !== null;
  } catch {
    return false;
  }
}

function tooMany(db, ip, kind, config, nowSec) {
  return dbApi.countFailures(db, ip, kind, nowSec - config.loginIpWindowSec) >= config.loginIpLimit;
}

function checkPasswordShape(password, password2) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    return 'Use a password of 12 to 128 characters.';
  }
  if (password !== password2) return 'The passwords do not match.';
  return null;
}

function checkUsername(username) {
  if (typeof username !== 'string' || !/^[A-Za-z0-9._-]{1,32}$/.test(username)) {
    return 'Use a username of letters, numbers, dots, dashes, or underscores (up to 32).';
  }
  return null;
}

async function createAdminAccount(db, config, { username, password }) {
  const totp = newTotp(username);
  const passwordHash = await hashPassword(password, config);
  dbApi.insertAdmin(db, { username, passwordHash, totpSecret: totp.base32 });
  dbApi.deleteSetupToken(db);
  return totp;
}

async function authenticate(db, config, { username, password, totp, ip, nowSec }) {
  const admin = dbApi.getAdmin(db);
  if (admin && admin.locked_until && admin.locked_until > nowSec) {
    return { ok: false, status: 429, error: 'This account is locked. Try again in a few minutes.' };
  }
  if (tooMany(db, ip, 'login', config, nowSec)) {
    return { ok: false, status: 429, error: 'Too many attempts. Try again in a few minutes.' };
  }

  const dummy = await dummyHash(db, config);
  const userOk = Boolean(admin) && sameString(admin.username, username || '');
  let passOk = false;
  try {
    passOk = await argon2.verify(userOk ? admin.password_hash : dummy, String(password || ''));
  } catch {
    passOk = false;
  }
  const totpOk = userOk && passOk && admin.totp_confirmed === 1 && verifyTotp(admin.totp_secret, totp, admin.username);
  if (!userOk || !passOk || !totpOk) {
    recordFailure(db, config, admin, ip, nowSec);
    return { ok: false, status: 401, error: 'Invalid credentials.' };
  }
  dbApi.clearLoginFailures(db);
  dbApi.insertAttempt(db, { ts: nowSec, ip, kind: 'login', success: true });
  return { ok: true, username: admin.username };
}

function recordFailure(db, config, admin, ip, nowSec) {
  const run = db.transaction(() => {
    dbApi.insertAttempt(db, { ts: nowSec, ip, kind: 'login', success: false });
    if (!admin) return;
    const fails = admin.failed_logins + 1;
    if (fails >= config.loginLockoutAfter) {
      dbApi.setLoginFailure(db, { failedLogins: 0, lockedUntil: nowSec + config.loginLockoutSec });
    } else {
      dbApi.setLoginFailure(db, { failedLogins: fails, lockedUntil: admin.locked_until || null });
    }
  });
  run();
}

async function dummyHash(db, config) {
  const existing = dbApi.getSetting(db, 'dummy_argon');
  if (existing) return existing;
  const hash = await hashPassword('dummy-password-not-used', config);
  dbApi.setSetting(db, 'dummy_argon', hash);
  return hash;
}

module.exports = {
  issueSetupToken,
  setupTokenValid,
  verifyTotp,
  totpForSecret,
  tooMany,
  checkPasswordShape,
  checkUsername,
  createAdminAccount,
  authenticate,
};
