'use strict';

// Normative decisions for the door contract.
// The server and the Pico (MicroPython) must match decideOnline / decideOffline
// and the schedule rules. The ESP-01 must match classifyOpen.
// tools/self-test.js locks the worked examples in contract/examples/vectors.json.

const crypto = require('crypto');

const LIMITS = {
  ONLINE_DECISION_TIMEOUT_MS: 1200,
  UID_DEBOUNCE_MS: 2000,
  HEARTBEAT_S: 30,
  MQTT_KEEPALIVE_S: 60,
  OFFLINE_AFTER_S: 90,
  // Reader firmware 0.6.0 turns Wi-Fi off between cards and says sleeping:true.
  // Two missed 10-minute check-ins, plus margin, before it is offline.
  READER_SLEEP_OFFLINE_S: 1500,
  OPEN_DEFAULT_MS: 3000,
  OPEN_MIN_MS: 200,
  OPEN_MAX_MS: 10000,
  OPEN_SKEW_S: 30,
  NONCE_RING: 32,
  ALLOWLIST_MAX_ENTRIES: 100,
  LOG_BATCH_MAX: 10,
  LOG_QUEUE_MAX: 50,
};

const OPEN_SOURCES = new Set(['server', 'reader']);
const OPEN_REASONS = new Set(['tag', 'manual', 'offline']);

function decodeKey(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('key must be 64 hex characters (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

function normalizeUid(uid) {
  if (typeof uid !== 'string') {
    throw new Error('uid must be a string');
  }
  const cleaned = uid.replace(/[:\s]/g, '').toUpperCase();
  if (!/^(?:[0-9A-F]{8}|[0-9A-F]{14}|[0-9A-F]{20})$/.test(cleaned)) {
    throw new Error('uid must be 4, 7, or 10 bytes of hex');
  }
  return cleaned;
}

function hmacHex(keyHex, text) {
  return crypto.createHmac('sha256', decodeKey(keyHex)).update(text, 'utf8').digest('hex');
}

function allowlistHash(keyHex, uid) {
  return hmacHex(keyHex, normalizeUid(uid));
}

function openCanonical(cmd) {
  return `v1|${cmd.id}|${cmd.ts}|${cmd.nonce}|${cmd.duration_ms}|${cmd.source}|${cmd.reason}`;
}

function signOpen(secretHex, fields) {
  const cmd = {
    schema: 1,
    id: fields.id,
    ts: fields.ts,
    nonce: fields.nonce,
    duration_ms: fields.duration_ms,
    source: fields.source,
    reason: fields.reason,
  };
  cmd.mac = hmacHex(secretHex, openCanonical(cmd));
  return cmd;
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length || a.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a.toLowerCase()), Buffer.from(b.toLowerCase()));
}

function posMod(value, divisor) {
  return ((value % divisor) + divisor) % divisor;
}

// Wall time for a schedule. `ts + offset` is read back as if it were UTC.
// 1970-01-01 is Thursday, ISO weekday 4. Floor division, then a positive remainder,
// so times before 1970 still land on the right weekday.
function civilFromUnix(ts, offsetMin) {
  if (!Number.isInteger(ts)) throw new Error('ts must be an integer');
  if (!Number.isInteger(offsetMin)) throw new Error('utc_offset_min must be an integer');
  const local = ts + offsetMin * 60;
  const days = Math.floor(local / 86400);
  const seconds = posMod(local, 86400);
  const minutes = Math.floor(seconds / 60);
  return {
    weekday: posMod(days + 3, 7) + 1,
    minutes,
  };
}

function parseClock(hh, mm) {
  const hour = Number(hh);
  const minute = Number(mm);
  if (hour > 23 || minute > 59) throw new Error('bad schedule time');
  return hour * 60 + minute;
}

// sch is "days,HH:MM-HH:MM". days is "*", a list "1,3,5", or ranges "1-5".
// Monday is 1, Sunday is 7. A window with end < start crosses midnight.
// Start is inclusive, end is exclusive. start === end matches nothing.
function parseSchedule(sch) {
  if (sch == null || sch === '') return null;
  if (typeof sch !== 'string') throw new Error('sch must be a string');
  const match = /^([0-9*\-,]+),(\d{2}):(\d{2})-(\d{2}):(\d{2})$/.exec(sch);
  if (!match) throw new Error('bad schedule');
  const start = parseClock(match[2], match[3]);
  const end = parseClock(match[4], match[5]);
  if (match[1] === '*') return { days: null, start, end };
  const days = new Set();
  for (const token of match[1].split(',')) {
    const range = /^([1-7])(?:-([1-7]))?$/.exec(token);
    if (!range) throw new Error('bad schedule days');
    const from = Number(range[1]);
    const to = range[2] == null ? from : Number(range[2]);
    if (to < from) throw new Error('bad schedule range');
    for (let day = from; day <= to; day += 1) days.add(day);
  }
  return { days, start, end };
}

function timeInWindow(minutes, start, end) {
  if (start === end) return false;
  if (end < start) return minutes >= start || minutes < end;
  return minutes >= start && minutes < end;
}

function scheduleAllows(ts, offsetMin, sch) {
  const window = parseSchedule(sch);
  if (!window) return true;
  const civil = civilFromUnix(ts, offsetMin);
  if (window.days && !window.days.has(civil.weekday)) return false;
  return timeInWindow(civil.minutes, window.start, window.end);
}

function decideOnline({ tag, ts, utcOffsetMin }) {
  if (!tag) return { granted: false, reason: 'unknown' };
  if (!tag.enabled) return { granted: false, reason: 'disabled' };
  if (!Number.isInteger(ts)) return { granted: false, reason: 'time_unsynced' };
  if (Number.isInteger(tag.exp) && ts >= tag.exp) return { granted: false, reason: 'expired' };
  try {
    if (!scheduleAllows(ts, utcOffsetMin, tag.sch)) {
      return { granted: false, reason: 'outside_hours' };
    }
  } catch {
    return { granted: false, reason: 'outside_hours' };
  }
  return { granted: true, reason: 'ok' };
}

// Offline list contains enabled tags only. A disabled tag is simply absent.
function decideOffline({ keyHex, uid, entries, ts, utcOffsetMin }) {
  let hash;
  try {
    hash = allowlistHash(keyHex, uid);
  } catch {
    return { granted: false, reason: 'unknown' };
  }
  if (!Number.isInteger(ts)) return { granted: false, reason: 'time_unsynced' };
  const entry = (entries || []).find((item) => item && item.h === hash);
  if (!entry) return { granted: false, reason: 'unknown' };
  if (Number.isInteger(entry.exp) && ts >= entry.exp) {
    return { granted: false, reason: 'expired' };
  }
  try {
    if (!scheduleAllows(ts, utcOffsetMin, entry.sch)) {
      return { granted: false, reason: 'outside_hours' };
    }
  } catch {
    return { granted: false, reason: 'outside_hours' };
  }
  return { granted: true, reason: 'offline_ok' };
}

function isWellFormedOpen(cmd) {
  if (!cmd || typeof cmd !== 'object') return false;
  if (cmd.schema !== 1) return false;
  if (typeof cmd.id !== 'string' || !/^[0-9a-f]{32}$/.test(cmd.id)) return false;
  if (typeof cmd.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(cmd.nonce)) return false;
  if (typeof cmd.mac !== 'string' || !/^[0-9a-f]{64}$/.test(cmd.mac)) return false;
  if (!Number.isInteger(cmd.ts)) return false;
  if (!Number.isInteger(cmd.duration_ms)) return false;
  if (!OPEN_SOURCES.has(cmd.source)) return false;
  if (!OPEN_REASONS.has(cmd.reason)) return false;
  return true;
}

// Check order is part of the contract. The nonce is stored only when a pulse starts.
function classifyOpen({ now, cmd, secretHex, seenNonces, busy }) {
  if (!isWellFormedOpen(cmd)) return { ok: false, reason: 'malformed', storeNonce: false };
  const expected = hmacHex(secretHex, openCanonical(cmd));
  if (!timingSafeEqualHex(expected, cmd.mac)) {
    return { ok: false, reason: 'bad_mac', storeNonce: false };
  }
  if (!Number.isInteger(now)) return { ok: false, reason: 'time_unsynced', storeNonce: false };
  if (seenNonces && seenNonces.has(cmd.nonce)) {
    return { ok: false, reason: 'replay', storeNonce: false };
  }
  if (Math.abs(now - cmd.ts) > LIMITS.OPEN_SKEW_S) {
    return { ok: false, reason: 'stale', storeNonce: false };
  }
  if (cmd.duration_ms < LIMITS.OPEN_MIN_MS || cmd.duration_ms > LIMITS.OPEN_MAX_MS) {
    return { ok: false, reason: 'duration', storeNonce: false };
  }
  if (busy) return { ok: false, reason: 'busy', storeNonce: false };
  return { ok: true, reason: 'opened', storeNonce: true };
}

module.exports = {
  LIMITS,
  OPEN_SOURCES,
  OPEN_REASONS,
  decodeKey,
  normalizeUid,
  hmacHex,
  allowlistHash,
  openCanonical,
  signOpen,
  civilFromUnix,
  parseSchedule,
  scheduleAllows,
  decideOnline,
  decideOffline,
  isWellFormedOpen,
  classifyOpen,
};
