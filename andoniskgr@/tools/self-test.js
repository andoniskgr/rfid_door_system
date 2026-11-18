'use strict';

// Contract checks that do not need a broker or hardware.
//   node tools/self-test.js

const fs = require('fs');
const path = require('path');
const {
  allowlistHash,
  civilFromUnix,
  classifyOpen,
  decideOffline,
  decideOnline,
  normalizeUid,
  openCanonical,
  parseSchedule,
  scheduleAllows,
  signOpen,
} = require('../contract/policy');
const { buildConnectPacket, buildPublishPacket } = require('./mqtt');

const root = path.join(__dirname, '..');
const vectors = JSON.parse(fs.readFileSync(path.join(root, 'contract/examples/vectors.json'), 'utf8'));
let failed = 0;

function check(cond, message) {
  if (cond) {
    console.log(`ok  ${message}`);
    return;
  }
  failed += 1;
  console.error(`FAIL  ${message}`);
}

function at(iso) {
  return Math.floor(Date.parse(iso) / 1000);
}

function main() {
  const open = vectors.open;
  check(openCanonical(open) === vectors.canonical, 'open canonical string');
  const resigned = signOpen(vectors.open_secret_hex, open);
  check(resigned.mac === open.mac, 'open MAC matches vectors.json');
  check(allowlistHash(vectors.allowlist_key_hex, vectors.uid) === vectors.uid_hash, 'allowlist hash');
  check(normalizeUid('a1:b2:c3:d4') === 'A1B2C3D4', 'UID colon form normalizes');
  check(allowlistHash(vectors.allowlist_key_hex, 'a1:b2:c3:d4') === vectors.uid_hash, 'hash uses normalized UID');

  const savedOpen = JSON.parse(fs.readFileSync(path.join(root, 'contract/examples/open.json'), 'utf8'));
  check(JSON.stringify(savedOpen) === JSON.stringify(open), 'examples/open.json is the signed vector');

  const allowlist = JSON.parse(fs.readFileSync(path.join(root, 'contract/examples/allowlist.json'), 'utf8'));
  check(allowlist.entries[0].h === vectors.uid_hash, 'allowlist example uses the vector hash');
  check(allowlist.version === 3 && allowlist.utc_offset_min === 120, 'allowlist version and offset');

  check(civilFromUnix(0, 0).weekday === 4, '1970-01-01 is Thursday');
  check(civilFromUnix(-1, 0).weekday === 3, 'the second before 1970 is Wednesday');
  check(civilFromUnix(at('2026-11-13T15:04:00Z'), 0).weekday === 5, '2026-11-13 is Friday');

  const friday = at('2026-11-13T15:04:00Z');
  const weekdays = '1-5,08:00-20:00';
  check(scheduleAllows(friday, 0, weekdays), 'Friday 15:04 is inside 08:00-20:00');
  check(!scheduleAllows(at('2026-11-13T21:00:00Z'), 0, weekdays), 'Friday 21:00 is outside');
  check(!scheduleAllows(at('2026-11-14T12:00:00Z'), 0, weekdays), 'Saturday is outside Mon-Fri');
  check(scheduleAllows(at('2026-11-13T08:00:00Z'), 0, weekdays), '08:00 is inside (start inclusive)');
  check(!scheduleAllows(at('2026-11-13T20:00:00Z'), 0, weekdays), '20:00 is outside (end exclusive)');
  check(scheduleAllows(at('2026-11-13T06:30:00Z'), 120, weekdays), 'UTC 06:30 with +120 min is local 08:30');
  check(scheduleAllows(at('2026-11-13T10:00:00Z'), -120, weekdays), 'UTC 10:00 with -120 min is local 08:00');

  const overnight = '*,22:00-06:00';
  check(scheduleAllows(at('2026-11-14T23:00:00Z'), 0, overnight), '23:00 is inside 22:00-06:00');
  check(scheduleAllows(at('2026-11-15T05:59:00Z'), 0, overnight), '05:59 is inside 22:00-06:00');
  check(!scheduleAllows(at('2026-11-15T06:00:00Z'), 0, overnight), '06:00 is outside 22:00-06:00');
  check(!scheduleAllows(at('2026-11-14T21:59:00Z'), 0, overnight), '21:59 is outside 22:00-06:00');
  check(!scheduleAllows(friday, 0, '1-5,08:00-08:00'), 'zero-length window matches nothing');
  check(scheduleAllows(friday, 0, null), 'omitted schedule is all hours');

  let rejected = false;
  try { parseSchedule('5-1,08:00-20:00'); } catch { rejected = true; }
  check(rejected, 'descending day range is rejected');

  const entries = allowlist.entries;
  const offlineHit = decideOffline({
    keyHex: vectors.allowlist_key_hex,
    uid: 'A1B2C3D4',
    entries,
    ts: friday,
    utcOffsetMin: 0,
  });
  check(offlineHit.granted && offlineHit.reason === 'offline_ok', 'known tag during hours is offline_ok');
  // Friday 15:04 UTC is 17:04 at offset +120, still inside 08:00-20:00.
  const offlineLocal = decideOffline({
    keyHex: vectors.allowlist_key_hex,
    uid: vectors.uid,
    entries,
    ts: friday,
    utcOffsetMin: allowlist.utc_offset_min,
  });
  check(offlineLocal.reason === 'offline_ok', 'example allowlist allows Friday 17:04 local');

  const missed = decideOffline({
    keyHex: vectors.allowlist_key_hex,
    uid: 'DEADBEEF',
    entries,
    ts: friday,
    utcOffsetMin: 0,
  });
  check(!missed.granted && missed.reason === 'unknown', 'absent tag is unknown');
  const noClock = decideOffline({
    keyHex: vectors.allowlist_key_hex,
    uid: vectors.uid,
    entries,
    ts: null,
    utcOffsetMin: 0,
  });
  check(noClock.reason === 'time_unsynced', 'offline with no clock is time_unsynced');
  const expired = decideOffline({
    keyHex: vectors.allowlist_key_hex,
    uid: vectors.uid,
    entries,
    ts: entries[0].exp,
    utcOffsetMin: 0,
  });
  check(expired.reason === 'expired', 'ts equal to exp is expired');

  const online = decideOnline({
    tag: { enabled: true, exp: null, sch: weekdays },
    ts: friday,
    utcOffsetMin: 0,
  });
  check(online.reason === 'ok', 'online grant reason is ok');
  const disabled = decideOnline({
    tag: { enabled: false, exp: null, sch: null },
    ts: friday,
    utcOffsetMin: 0,
  });
  check(disabled.reason === 'disabled', 'disabled tag is disabled online');
  check(decideOnline({ tag: null, ts: friday, utcOffsetMin: 0 }).reason === 'unknown', 'missing tag is unknown');

  const seen = new Set();
  const good = classifyOpen({
    now: open.ts,
    cmd: open,
    secretHex: vectors.open_secret_hex,
    seenNonces: seen,
    busy: false,
  });
  check(good.ok && good.reason === 'opened' && good.storeNonce, 'fresh signed command opens');
  seen.add(open.nonce);
  const replay = classifyOpen({
    now: open.ts,
    cmd: open,
    secretHex: vectors.open_secret_hex,
    seenNonces: seen,
    busy: false,
  });
  check(replay.reason === 'replay' && !replay.storeNonce, 'reused nonce is replay');

  const stale = classifyOpen({
    now: open.ts + 31,
    cmd: open,
    secretHex: vectors.open_secret_hex,
    seenNonces: new Set(),
    busy: false,
  });
  check(stale.reason === 'stale', '31 seconds of skew is stale');
  const edge = classifyOpen({
    now: open.ts + 30,
    cmd: open,
    secretHex: vectors.open_secret_hex,
    seenNonces: new Set(),
    busy: false,
  });
  check(edge.reason === 'opened', '30 seconds of skew is still fresh');

  const flipped = { ...open, mac: open.mac.replace(/^./, open.mac[0] === 'a' ? 'b' : 'a') };
  check(classifyOpen({
    now: open.ts, cmd: flipped, secretHex: vectors.open_secret_hex, seenNonces: new Set(), busy: false,
  }).reason === 'bad_mac', 'flipped MAC is bad_mac');

  check(classifyOpen({
    now: null, cmd: open, secretHex: vectors.open_secret_hex, seenNonces: new Set(), busy: false,
  }).reason === 'time_unsynced', 'actuator with no clock rejects the command');

  const tooLong = signOpen(vectors.open_secret_hex, { ...open, duration_ms: 10001 });
  check(classifyOpen({
    now: tooLong.ts, cmd: tooLong, secretHex: vectors.open_secret_hex, seenNonces: new Set(), busy: false,
  }).reason === 'duration', '10001 ms is over the hard maximum');
  const maxOk = signOpen(vectors.open_secret_hex, { ...open, nonce: 'ff'.repeat(16), duration_ms: 10000 });
  check(classifyOpen({
    now: maxOk.ts, cmd: maxOk, secretHex: vectors.open_secret_hex, seenNonces: new Set(), busy: false,
  }).reason === 'opened', '10000 ms is the hard maximum');

  check(classifyOpen({
    now: open.ts, cmd: open, secretHex: vectors.open_secret_hex, seenNonces: new Set(), busy: true,
  }).reason === 'busy', 'a pulse already running is busy');
  check(classifyOpen({
    now: open.ts, cmd: { ...open, schema: 2 }, secretHex: vectors.open_secret_hex, seenNonces: new Set(), busy: false,
  }).reason === 'malformed', 'schema 2 is malformed');

  check(scheduleAllows(friday, 0, '1,3,5,08:00-20:00'), 'Friday matches day list 1,3,5');
  check(!scheduleAllows(at('2026-11-12T12:00:00Z'), 0, '1,3,5,08:00-20:00'), 'Thursday is outside 1,3,5');
  const badEntry = decideOffline({
    keyHex: vectors.allowlist_key_hex,
    uid: vectors.uid,
    entries: [{ h: vectors.uid_hash, sch: 'not-a-schedule' }],
    ts: friday,
    utcOffsetMin: 0,
  });
  check(badEntry.reason === 'outside_hours', 'a broken schedule does not grant');

  const lwt = fs.readFileSync(path.join(root, 'contract/examples/status-lwt.json'), 'utf8').trim();
  check(lwt === '{"online":false,"reason":"lwt"}', 'Last Will payload is compact JSON');

  const connect = buildConnectPacket({
    clientId: 'door-reader-sim',
    username: 'door-reader',
    password: 'secret',
    keepalive: 30,
  });
  check(connect[0] === 0x10 && connect.includes(Buffer.from('MQTT')), 'CONNECT is MQTT 3.1.1');

  const qos1 = buildPublishPacket({ topic: 'door/actuator/open', payload: '{}', qos: 1, retain: false });
  check(qos1[0] === 0x32, 'open publish is QoS 1 and not retained');
  const retained = buildPublishPacket({ topic: 'door/reader/allowlist', payload: '{}', qos: 1, retain: true });
  check(retained[0] === 0x33, 'allowlist publish is QoS 1 and retained');

  if (failed) {
    console.error(`\n${failed} failed`);
    process.exit(1);
  }
  console.log('\nall contract checks passed');
}

main();
