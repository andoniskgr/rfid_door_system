'use strict';

const { formatTs } = require('./timeutil');
const { expiryToDateInput, splitSchedule } = require('./schedule');

const REASON_LABEL = {
  ok: 'Granted',
  offline_ok: 'Granted offline',
  manual: 'Manual open',
  unknown: 'Unknown tag',
  disabled: 'Disabled',
  expired: 'Expired',
  outside_hours: 'Outside allowed hours',
  time_unsynced: 'Clock not set',
  not_actuated: 'Door not reached',
  opened: 'Relay opened',
  stale: 'Command too old',
  replay: 'Replayed command',
  bad_mac: 'Bad signature',
  duration: 'Bad pulse length',
  busy: 'Relay busy',
  malformed: 'Bad command',
};

function reasonLabel(reason) {
  return REASON_LABEL[reason] || reason || '';
}

function presentEvent(row, timeZone) {
  return {
    id: row.id,
    ts: row.ts,
    time: formatTs(row.ts, timeZone),
    uid: row.uid || '',
    owner: row.owner_name || '',
    granted: row.granted === 1,
    reason: row.reason,
    reasonLabel: reasonLabel(row.reason),
    source: row.source,
    actuator: row.actuator_result || '',
    actuatorLabel: row.actuator_result ? reasonLabel(row.actuator_result) : '',
  };
}

function presentDevice(row, timeZone) {
  let payload = {};
  if (row.payload) {
    try { payload = JSON.parse(row.payload); } catch { payload = {}; }
  }
  return {
    role: row.role,
    title: row.role === 'reader' ? 'Entrance reader' : 'Door relay',
    online: row.online === 1,
    lastSeen: row.last_seen ? formatTs(row.last_seen, timeZone) : 'No heartbeat yet',
    fw: payload.fw || '',
    ip: payload.ip || '',
    ssid: typeof payload.ssid === 'string' ? payload.ssid.slice(0, 32) : '',
    rssi: Number.isInteger(payload.rssi) ? payload.rssi : null,
    allowlist: Number.isInteger(payload.allowlist_version) ? payload.allowlist_version : null,
    relay: payload.relay || '',
    logQueued: Number.isInteger(payload.log_queued) ? payload.log_queued : null,
  };
}

function presentTag(row, timeZone) {
  let schedule;
  try {
    schedule = splitSchedule(row.sch);
  } catch {
    schedule = { allHours: false, days: [], start: '', end: '', raw: row.sch };
  }
  return {
    uid: row.uid,
    name: row.name,
    enabled: row.enabled === 1,
    exp: expiryToDateInput(row.exp, timeZone),
    sch: row.sch || '',
    schedule,
  };
}

module.exports = { REASON_LABEL, reasonLabel, presentEvent, presentDevice, presentTag };
