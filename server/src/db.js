'use strict';

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

function openDatabase(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  migrate(db);
  return db;
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS admin (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      totp_secret TEXT NOT NULL,
      totp_confirmed INTEGER NOT NULL DEFAULT 0,
      failed_logins INTEGER NOT NULL DEFAULT 0,
      locked_until INTEGER
    );

    CREATE TABLE IF NOT EXISTS setup_tokens (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      token_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS recovery_tokens (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      token_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tags (
      uid TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      exp INTEGER,
      sch TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      ts INTEGER NOT NULL,
      uid TEXT,
      owner_name TEXT,
      granted INTEGER NOT NULL,
      reason TEXT NOT NULL,
      source TEXT NOT NULL,
      device TEXT,
      allowlist_version INTEGER,
      open_id TEXT,
      actuator_result TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_events_uid ON events(uid);
    CREATE INDEX IF NOT EXISTS idx_events_open ON events(open_id);

    CREATE TABLE IF NOT EXISTS devices (
      role TEXT PRIMARY KEY,
      online INTEGER NOT NULL DEFAULT 0,
      last_seen INTEGER,
      payload TEXT
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      ip TEXT NOT NULL,
      kind TEXT NOT NULL,
      success INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_attempts ON login_attempts(kind, ip, ts);

    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      expires INTEGER NOT NULL
    );
  `);

  const insertDevice = db.prepare('INSERT OR IGNORE INTO devices (role, online, last_seen, payload) VALUES (?, 0, NULL, NULL)');
  insertDevice.run('reader');
  insertDevice.run('actuator');

  const defaults = {
    allowlist_version: '1',
    telegram_unknown: '1',
    telegram_denied: '1',
    telegram_device: '1',
    telegram_manual: '1',
  };
  const setDefault = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
  for (const [key, value] of Object.entries(defaults)) setDefault.run(key, value);
}

function getSetting(db, key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(db, key, value) {
  db.prepare(`
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, String(value));
}

function getAdmin(db) {
  return db.prepare('SELECT * FROM admin WHERE id = 1').get() || null;
}

function insertAdmin(db, { username, passwordHash, totpSecret }) {
  db.prepare(`
    INSERT INTO admin (id, username, password_hash, totp_secret, totp_confirmed, failed_logins, locked_until)
    VALUES (1, ?, ?, ?, 0, 0, NULL)
  `).run(username, passwordHash, totpSecret);
}

function confirmTotp(db) {
  db.prepare('UPDATE admin SET totp_confirmed = 1, failed_logins = 0, locked_until = NULL WHERE id = 1').run();
}

function clearLoginFailures(db) {
  db.prepare('UPDATE admin SET failed_logins = 0, locked_until = NULL WHERE id = 1').run();
}

function setLoginFailure(db, { failedLogins, lockedUntil }) {
  db.prepare('UPDATE admin SET failed_logins = ?, locked_until = ? WHERE id = 1').run(failedLogins, lockedUntil);
}

function getSetupToken(db) {
  return db.prepare('SELECT token_hash, expires_at FROM setup_tokens WHERE id = 1').get() || null;
}

function saveSetupToken(db, tokenHash, expiresAt) {
  db.prepare(`
    INSERT INTO setup_tokens (id, token_hash, expires_at) VALUES (1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET token_hash = excluded.token_hash, expires_at = excluded.expires_at
  `).run(tokenHash, expiresAt);
}

function deleteSetupToken(db) {
  db.prepare('DELETE FROM setup_tokens WHERE id = 1').run();
}

function setPasswordHash(db, passwordHash) {
  db.prepare(`
    UPDATE admin SET password_hash = ?, failed_logins = 0, locked_until = NULL WHERE id = 1
  `).run(passwordHash);
}

function deleteSessions(db) {
  db.prepare('DELETE FROM sessions').run();
}

function getRecoveryToken(db) {
  return db.prepare('SELECT token_hash, expires_at FROM recovery_tokens WHERE id = 1').get() || null;
}

function saveRecoveryToken(db, tokenHash, expiresAt) {
  db.prepare(`
    INSERT INTO recovery_tokens (id, token_hash, expires_at) VALUES (1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET token_hash = excluded.token_hash, expires_at = excluded.expires_at
  `).run(tokenHash, expiresAt);
}

function deleteRecoveryToken(db) {
  db.prepare('DELETE FROM recovery_tokens WHERE id = 1').run();
}

function countFailures(db, ip, kind, since) {
  const row = db.prepare(`
    SELECT COUNT(*) AS n FROM login_attempts
    WHERE kind = ? AND ip = ? AND success = 0 AND ts > ?
  `).get(kind, ip, since);
  return row.n;
}

function insertAttempt(db, { ts, ip, kind, success }) {
  db.prepare('INSERT INTO login_attempts (ts, ip, kind, success) VALUES (?, ?, ?, ?)').run(ts, ip, kind, success ? 1 : 0);
}

function pruneAttempts(db, beforeTs) {
  db.prepare('DELETE FROM login_attempts WHERE ts < ?').run(beforeTs);
}

function getTag(db, uid) {
  return db.prepare('SELECT * FROM tags WHERE uid = ?').get(uid) || null;
}

function listTags(db) {
  return db.prepare('SELECT * FROM tags ORDER BY name COLLATE NOCASE, uid').all();
}

function insertTag(db, tag) {
  db.prepare(`
    INSERT INTO tags (uid, name, enabled, exp, sch, created_at, updated_at)
    VALUES (@uid, @name, @enabled, @exp, @sch, @created_at, @updated_at)
  `).run(tag);
}

function updateTag(db, uid, fields) {
  db.prepare(`
    UPDATE tags SET name = ?, enabled = ?, exp = ?, sch = ?, updated_at = ? WHERE uid = ?
  `).run(fields.name, fields.enabled, fields.exp, fields.sch, fields.updated_at, uid);
}

function setTagEnabled(db, uid, enabled, updatedAt) {
  db.prepare('UPDATE tags SET enabled = ?, updated_at = ? WHERE uid = ?').run(enabled ? 1 : 0, updatedAt, uid);
}

function deleteTag(db, uid) {
  return db.prepare('DELETE FROM tags WHERE uid = ?').run(uid).changes;
}

function listEnabledTags(db) {
  return db.prepare('SELECT uid, exp, sch FROM tags WHERE enabled = 1 ORDER BY uid').all();
}

function getEvent(db, id) {
  return db.prepare('SELECT * FROM events WHERE id = ?').get(id) || null;
}

function insertEvent(db, event) {
  return db.prepare(`
    INSERT OR IGNORE INTO events (
      id, ts, uid, owner_name, granted, reason, source, device, allowlist_version, open_id, actuator_result
    ) VALUES (
      @id, @ts, @uid, @owner_name, @granted, @reason, @source, @device, @allowlist_version, @open_id, @actuator_result
    )
  `).run(event).changes;
}

function setEventOpenId(db, id, openId) {
  db.prepare('UPDATE events SET open_id = ? WHERE id = ? AND open_id IS NULL').run(openId, id);
}

function updateEventDecision(db, id, { granted, reason, openId }) {
  db.prepare('UPDATE events SET granted = ?, reason = ?, open_id = ? WHERE id = ?')
    .run(granted ? 1 : 0, reason, openId, id);
}

function setActuatorResult(db, openId, result) {
  return db.prepare('UPDATE events SET actuator_result = ? WHERE open_id = ?').run(result, openId).changes;
}

function lastEventTsForUid(db, uid) {
  const row = db.prepare('SELECT ts FROM events WHERE uid = ? ORDER BY ts DESC LIMIT 1').get(uid);
  return row ? row.ts : null;
}

function listEvents(db, filters) {
  const where = [];
  const params = {};
  if (filters.uid) {
    where.push('uid LIKE :uid');
    params.uid = `%${String(filters.uid).replace(/[%_]/g, '')}%`;
  }
  if (filters.granted === 0 || filters.granted === 1) {
    where.push('granted = :granted');
    params.granted = filters.granted;
  }
  if (filters.reason) {
    where.push('reason = :reason');
    params.reason = filters.reason;
  }
  if (Number.isInteger(filters.from)) {
    where.push('ts >= :fromTs');
    params.fromTs = filters.from;
  }
  if (Number.isInteger(filters.to)) {
    where.push('ts < :toTs');
    params.toTs = filters.to;
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = db.prepare(`SELECT COUNT(*) AS n FROM events ${clause}`).get(params).n;
  params.limit = filters.limit;
  params.offset = filters.offset;
  const rows = db.prepare(`
    SELECT * FROM events ${clause} ORDER BY ts DESC, id DESC LIMIT :limit OFFSET :offset
  `).all(params);
  return { total, rows };
}

function listUnregistered(db) {
  return db.prepare(`
    SELECT uid, MAX(ts) AS last_ts, COUNT(*) AS seen
    FROM events
    WHERE reason = 'unknown' AND uid IS NOT NULL AND uid != ''
      AND uid NOT IN (SELECT uid FROM tags)
    GROUP BY uid
    ORDER BY last_ts DESC
    LIMIT 100
  `).all();
}

function listDevices(db) {
  return db.prepare("SELECT * FROM devices WHERE role IN ('reader', 'actuator') ORDER BY role DESC").all();
}

function getDevice(db, role) {
  return db.prepare('SELECT * FROM devices WHERE role = ?').get(role);
}

function updateDevice(db, role, { online, lastSeen, payload }) {
  db.prepare('UPDATE devices SET online = ?, last_seen = ?, payload = ? WHERE role = ?')
    .run(online ? 1 : 0, lastSeen, payload, role);
}

function readSession(db, sid) {
  const row = db.prepare('SELECT data, expires FROM sessions WHERE sid = ?').get(sid);
  if (!row || row.expires < Date.now()) return null;
  try {
    return JSON.parse(row.data);
  } catch {
    return null;
  }
}

module.exports = {
  openDatabase,
  getSetting,
  setSetting,
  getAdmin,
  insertAdmin,
  confirmTotp,
  clearLoginFailures,
  setLoginFailure,
  getSetupToken,
  saveSetupToken,
  deleteSetupToken,
  setPasswordHash,
  deleteSessions,
  getRecoveryToken,
  saveRecoveryToken,
  deleteRecoveryToken,
  countFailures,
  insertAttempt,
  pruneAttempts,
  getTag,
  listTags,
  insertTag,
  updateTag,
  setTagEnabled,
  deleteTag,
  listEnabledTags,
  getEvent,
  insertEvent,
  setEventOpenId,
  updateEventDecision,
  setActuatorResult,
  lastEventTsForUid,
  listEvents,
  listUnregistered,
  listDevices,
  getDevice,
  updateDevice,
  readSession,
};
