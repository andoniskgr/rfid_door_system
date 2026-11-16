'use strict';

const crypto = require('crypto');
const {
  LIMITS,
  allowlistHash,
  decideOnline,
  normalizeUid,
  signOpen,
} = require('../../contract/policy');
const dbApi = require('./db');
const { presentDevice, presentEvent } = require('./present');
const { currentOffsetMin } = require('./timeutil');

const DECISION_REASONS = new Set([
  'ok', 'offline_ok', 'manual', 'unknown', 'disabled', 'expired',
  'outside_hours', 'time_unsynced', 'not_actuated',
]);

function randomId() {
  return crypto.randomBytes(16).toString('hex');
}

function cleanToken(value, pattern) {
  return typeof value === 'string' && pattern.test(value) ? value : null;
}

function createDoor({ db, config, transport, telegram, hub, now = () => Math.floor(Date.now() / 1000) }) {
  const lastUidAt = new Map();
  let lastManualAt = 0;
  const pendingResults = new Map();
  const denyHits = new Map();
  const denyNotified = new Map();
  const unknownNotified = new Map();

  function offset() {
    return currentOffsetMin(config.tz, new Date(now() * 1000));
  }

  function broadcastEvent(row) {
    if (!row) return;
    hub.broadcast({ type: 'event', event: presentEvent(row, config.tz) });
  }

  function broadcastDevices() {
    hub.broadcast({
      type: 'devices',
      mqtt: Boolean(transport.connected),
      devices: dbApi.listDevices(db).map((row) => presentDevice(row, config.tz)),
    });
  }

  function rememberResult(openId, result) {
    if (!openId || !result) return;
    const changes = dbApi.setActuatorResult(db, openId, result);
    if (changes === 0) {
      pendingResults.set(openId, result);
      if (pendingResults.size > 100) {
        const oldest = pendingResults.keys().next().value;
        pendingResults.delete(oldest);
      }
    }
  }

  function insert(event) {
    if (event.open_id && pendingResults.has(event.open_id)) {
      event.actuator_result = pendingResults.get(event.open_id);
      pendingResults.delete(event.open_id);
    }
    const changes = dbApi.insertEvent(db, {
      actuator_result: null,
      device: null,
      allowlist_version: null,
      open_id: null,
      uid: null,
      owner_name: '',
      ...event,
      granted: event.granted ? 1 : 0,
    });
    if (changes === 1) broadcastEvent(dbApi.getEvent(db, event.id));
    return changes === 1;
  }

  async function publish(topic, message, retain) {
    await transport.publish(topic, JSON.stringify(message), { qos: 1, retain });
  }

  function debounced(uid, ts) {
    const prev = lastUidAt.get(uid);
    if (prev != null && ts - prev < LIMITS.UID_DEBOUNCE_MS / 1000) return true;
    lastUidAt.set(uid, ts);
    if (lastUidAt.size > 200) {
      for (const [key, at] of lastUidAt) {
        if (ts - at > 30) lastUidAt.delete(key);
      }
    }
    return false;
  }

  function noteDeny(uid, ts) {
    const hits = (denyHits.get(uid) || []).filter((at) => ts - at < 10 * 60);
    hits.push(ts);
    denyHits.set(uid, hits);
    const last = denyNotified.get(uid) || 0;
    if (hits.length >= 3 && ts - last >= 30 * 60) {
      denyNotified.set(uid, ts);
      telegram.notify('denied', `${uid} was denied ${hits.length} times in 10 minutes.`);
    }
  }

  function noteUnknown(uid) {
    const ts = now();
    const last = unknownNotified.get(uid) || 0;
    if (ts - last < 10 * 60) return;
    unknownNotified.set(uid, ts);
    telegram.notify('unknown', `Unknown tag ${uid} at the entrance.`);
  }

  async function publishAllowlist() {
    const enabled = dbApi.listEnabledTags(db);
    if (enabled.length > LIMITS.ALLOWLIST_MAX_ENTRIES) {
      console.error('allowlist capped at', LIMITS.ALLOWLIST_MAX_ENTRIES);
    }
    const tags = enabled.slice(0, LIMITS.ALLOWLIST_MAX_ENTRIES);
    const entries = tags.map((tag) => {
      const entry = { h: allowlistHash(config.allowlistKey, tag.uid) };
      if (Number.isInteger(tag.exp)) entry.exp = tag.exp;
      if (tag.sch) entry.sch = tag.sch;
      return entry;
    }).sort((a, b) => (a.h < b.h ? -1 : 1));
    const utcOffset = offset();
    const fingerprint = JSON.stringify({ entries, utcOffset });
    let version = Number(dbApi.getSetting(db, 'allowlist_version') || '1');
    const previous = dbApi.getSetting(db, 'allowlist_fingerprint');
    if (previous != null && previous !== fingerprint) version += 1;
    dbApi.setSetting(db, 'allowlist_version', String(version));
    dbApi.setSetting(db, 'allowlist_fingerprint', fingerprint);
    dbApi.setSetting(db, 'allowlist_offset', String(utcOffset));
    const body = {
      schema: 1,
      id: randomId(),
      ts: now(),
      version,
      hash: 'hmac-sha256',
      utc_offset_min: utcOffset,
      entries,
    };
    await publish('door/reader/allowlist', body, true);
    console.log(`allowlist version ${version}, ${entries.length} tags`);
    return body;
  }

  async function sendOpen({ source, reason }) {
    const cmd = signOpen(config.openSecret, {
      id: randomId(),
      ts: now(),
      nonce: randomId(),
      duration_ms: config.openMs,
      source,
      reason,
    });
    await publish('door/actuator/open', cmd, false);
    return cmd;
  }

  async function onUid(msg) {
    const id = cleanToken(msg.id, /^[0-9a-f]{32}$/);
    if (!id || !Number.isInteger(msg.ts)) return;
    if (dbApi.getEvent(db, id)) return;
    let uid;
    try {
      uid = normalizeUid(msg.uid);
    } catch {
      await publish('door/reader/feedback', {
        schema: 1, id, ts: now(), granted: false, reason: 'unknown',
      }, false);
      return;
    }
    const ts = now();
    if (debounced(uid, ts)) return;

    const tag = dbApi.getTag(db, uid);
    const decision = decideOnline({
      tag: tag ? { enabled: tag.enabled === 1, exp: tag.exp, sch: tag.sch } : null,
      ts,
      utcOffsetMin: offset(),
    });
    let openId = null;
    let reason = decision.reason;
    let granted = decision.granted;
    // Insert before the pulse so a redelivered read cannot open the door twice.
    insert({
      id,
      ts,
      uid,
      owner_name: tag ? tag.name : '',
      granted,
      reason,
      source: 'server',
      device: cleanToken(msg.device, /^[a-z0-9_-]{1,32}$/) || 'entrance',
      allowlist_version: Number(dbApi.getSetting(db, 'allowlist_version') || '1'),
      open_id: null,
    });
    if (granted) {
      try {
        const cmd = await sendOpen({ source: 'server', reason: 'tag' });
        openId = cmd.id;
      } catch (err) {
        console.error('open command', err.message);
        granted = false;
        reason = 'not_actuated';
      }
      dbApi.updateEventDecision(db, id, { granted, reason, openId });
      broadcastEvent(dbApi.getEvent(db, id));
    }
    await publish('door/reader/feedback', {
      schema: 1, id, ts, granted, reason,
    }, false).catch((err) => console.error('feedback', err.message));
    console.log(`uid ${uid} ${granted ? 'granted' : 'denied'} ${reason}`);
    if (decision.reason === 'unknown') noteUnknown(uid);
    if (!decision.granted) noteDeny(uid, ts);
  }

  function onLocal(msg) {
    const id = cleanToken(msg.id, /^[0-9a-f]{32}$/);
    if (!id || !Number.isInteger(msg.ts)) return;
    // A late local decision must not open the door. The Pico already acted.
    const existing = dbApi.getEvent(db, id);
    const openId = msg.open_id == null ? null : cleanToken(msg.open_id, /^[0-9a-f]{32}$/);
    if (existing) {
      if (openId && !existing.open_id) dbApi.setEventOpenId(db, id, openId);
      return;
    }
    let uid = null;
    try { uid = normalizeUid(msg.uid); } catch { uid = null; }
    const reason = DECISION_REASONS.has(msg.reason) ? msg.reason : 'unknown';
    const tag = uid ? dbApi.getTag(db, uid) : null;
    insert({
      id,
      ts: msg.ts,
      uid,
      owner_name: tag ? tag.name : '',
      granted: msg.granted === true && reason !== 'unknown',
      reason,
      source: 'reader',
      device: cleanToken(msg.device, /^[a-z0-9_-]{1,32}$/) || 'entrance',
      allowlist_version: Number.isInteger(msg.allowlist_version) ? msg.allowlist_version : null,
      open_id: openId,
    });
  }

  function onLog(msg) {
    if (!Array.isArray(msg.entries)) return;
    if (msg.entries.length > LIMITS.LOG_BATCH_MAX) {
      console.error('log batch truncated to', LIMITS.LOG_BATCH_MAX);
    }
    for (const entry of msg.entries.slice(0, LIMITS.LOG_BATCH_MAX)) onLocal(entry);
  }

  function onStatus(role, msg) {
    const prev = dbApi.getDevice(db, role);
    const lwt = msg.online === false && msg.reason === 'lwt';
    const ts = now();
    const stale = Number.isInteger(msg.ts) && ts - msg.ts > LIMITS.OFFLINE_AFTER_S;
    const online = msg.online === true && !stale && !lwt;
    const first = prev.payload == null;
    dbApi.updateDevice(db, role, {
      online,
      lastSeen: ts,
      payload: JSON.stringify(msg),
    });
    if (!first && Boolean(prev.online) !== online) {
      const name = role === 'reader' ? 'Entrance reader' : 'Door relay';
      telegram.notify('device', `${name} is ${online ? 'online' : 'offline'}.`);
    }
    broadcastDevices();
  }

  function onResult(msg) {
    const id = cleanToken(msg.id, /^[0-9a-f]{32}$/);
    const reason = cleanToken(msg.reason, /^[a-z0-9_]{1,40}$/);
    if (!id || !reason) return;
    rememberResult(id, reason);
  }

  function handle(topic, msg) {
    let pending = null;
    if (topic === 'door/reader/uid') pending = onUid(msg);
    else if (topic === 'door/reader/local') onLocal(msg);
    else if (topic === 'door/reader/log') onLog(msg);
    else if (topic === 'door/reader/status') onStatus('reader', msg);
    else if (topic === 'door/actuator/status') onStatus('actuator', msg);
    else if (topic === 'door/actuator/result') onResult(msg);
    if (pending && typeof pending.catch === 'function') {
      pending.catch((err) => console.error('door message', topic, err.message));
    }
    return pending;
  }

  function sweep() {
    const ts = now();
    let changed = false;
    for (const row of dbApi.listDevices(db)) {
      if (!row.online || !row.last_seen) continue;
      if (ts - row.last_seen <= LIMITS.OFFLINE_AFTER_S) continue;
      dbApi.updateDevice(db, row.role, { online: false, lastSeen: row.last_seen, payload: row.payload });
      const name = row.role === 'reader' ? 'Entrance reader' : 'Door relay';
      telegram.notify('device', `${name} is offline.`);
      changed = true;
    }
    if (changed) broadcastDevices();
  }

  async function openNow(username) {
    const ts = now();
    if (ts - lastManualAt < LIMITS.UID_DEBOUNCE_MS / 1000) {
      const err = new Error('Wait a moment before opening again.');
      err.code = 'DEBOUNCE';
      throw err;
    }
    lastManualAt = ts;
    if (!transport.connected) {
      insert({
        id: randomId(),
        ts,
        uid: null,
        owner_name: username,
        granted: false,
        reason: 'not_actuated',
        source: 'manual',
        device: 'entrance',
      });
      const err = new Error('The broker is not connected. The door was not opened.');
      err.code = 'NO_MQTT';
      throw err;
    }
    const cmd = await sendOpen({ source: 'server', reason: 'manual' });
    insert({
      id: randomId(),
      ts,
      uid: null,
      owner_name: username,
      granted: true,
      reason: 'manual',
      source: 'manual',
      device: 'entrance',
      open_id: cmd.id,
    });
    telegram.notify('manual', `Manual open by ${username}.`);
    return cmd;
  }

  function snapshot() {
    return {
      type: 'snapshot',
      mqtt: Boolean(transport.connected),
      devices: dbApi.listDevices(db).map((row) => presentDevice(row, config.tz)),
      events: dbApi.listEvents(db, { limit: 30, offset: 0 }).rows.map((row) => presentEvent(row, config.tz)),
    };
  }

  return { handle, sweep, publishAllowlist, openNow, snapshot };
}

module.exports = { createDoor, randomId };
