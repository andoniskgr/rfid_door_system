'use strict';

const assert = require('node:assert/strict');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const test = require('node:test');
const { once } = require('node:events');
const { WebSocket } = require('ws');
const OTPAuth = require('otpauth');
const { civilFromUnix, classifyOpen } = require('../../contract/policy');
const { loadConfig } = require('../src/config');
const { openDatabase, getAdmin, getEvent, getTag, updateDevice } = require('../src/db');
const { issueSetupToken } = require('../src/auth');
const { createTelegram } = require('../src/telegram');
const { createDoor } = require('../src/door');
const { createApp, attachWebSocket, createHub } = require('../src/app');
const { backupDatabase, pruneBackups } = require('../src/backup');
const { expiryFromDate, buildSchedule, startOfLocalDay } = require('../src/schedule');
const { currentOffsetMin, localDay, localHm, shouldRunDaily } = require('../src/timeutil');

const SECRET = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const ALLOW = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

function baseEnv(dir) {
  return {
    HOST: '127.0.0.1',
    PORT: '3000',
    COOKIE_SECURE: 'false',
    TRUST_PROXY: 'false',
    SESSION_SECRET: '0123456789abcdef0123456789abcdef',
    TZ: 'UTC',
    DATA_DIR: dir,
    MQTT_HOST: '127.0.0.1',
    MQTT_PORT: '1883',
    MQTT_USER: 'door-server',
    MQTT_PASS: 'server-secret',
    DOOR_HMAC_SECRET: SECRET,
    ALLOWLIST_HMAC_KEY: ALLOW,
    DOOR_OPEN_MS: '3000',
    TELEGRAM_BOT_TOKEN: '',
    TELEGRAM_CHAT_ID: '',
  };
}

function fakeTransport() {
  const messages = [];
  return {
    messages,
    connected: true,
    async publish(topic, payload, opts) {
      messages.push({ topic, payload: JSON.parse(payload), opts });
    },
  };
}

class Agent {
  constructor(base) {
    this.base = base;
    this.jar = new Map();
  }

  cookieHeader() {
    return [...this.jar].map(([key, value]) => `${key}=${value}`).join('; ');
  }

  absorb(res) {
    const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    for (const line of list) {
      const pair = line.split(';')[0];
      const eq = pair.indexOf('=');
      this.jar.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
  }

  async fetch(urlPath, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    const cookie = this.cookieHeader();
    if (cookie) headers.cookie = cookie;
    const res = await fetch(this.base + urlPath, { redirect: 'manual', ...opts, headers });
    this.absorb(res);
    return res;
  }

  post(urlPath, fields) {
    return this.fetch(urlPath, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString(),
    });
  }
}

function csrfOf(html) {
  const match = /name="_csrf" value="([a-f0-9]+)"/.exec(html);
  assert.ok(match, 'csrf token missing');
  return match[1];
}

function totpCode(base32) {
  return new OTPAuth.TOTP({
    secret: OTPAuth.Secret.fromBase32(base32),
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
  }).generate();
}

async function start(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'door-'));
  const config = loadConfig(baseEnv(dir));
  Object.assign(config, overrides.config || {});
  config.argon = { memoryCost: 8192, timeCost: 2, parallelism: 1 };
  if (overrides.env) Object.assign(config, loadPatch(overrides.env));
  const db = openDatabase(config.dbPath);
  const token = issueSetupToken(db, Math.floor(Date.now() / 1000), config.setupTtlSec);
  const transport = fakeTransport();
  const sent = [];
  const telegram = createTelegram({
    config,
    db,
    fetchImpl: async (url, init) => {
      sent.push(JSON.parse(init.body));
      return { ok: true };
    },
  });
  const hub = createHub();
  const now = overrides.now || (() => Math.floor(Date.now() / 1000));
  const door = createDoor({ db, config, transport, telegram, hub, now });
  const app = createApp({ db, config, door });
  const server = http.createServer(app);
  attachWebSocket(server, { db, config, door, hub });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const agent = new Agent(`http://127.0.0.1:${port}`);
  return {
    dir, config, db, token, transport, sent, door, hub, agent, port,
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(() => resolve()));
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

function loadPatch(env) {
  const patch = {};
  if (env.COOKIE_SECURE != null) patch.cookieSecure = env.COOKIE_SECURE !== 'false';
  if (env.TELEGRAM_BOT_TOKEN) {
    patch.telegramToken = env.TELEGRAM_BOT_TOKEN;
    patch.telegramChat = env.TELEGRAM_CHAT_ID || '1';
  }
  return patch;
}

async function enroll(ctx) {
  let res = await ctx.agent.fetch('/setup');
  let html = await res.text();
  res = await ctx.agent.post('/setup', {
    _csrf: csrfOf(html),
    token: ctx.token,
    username: 'ada',
    password: 'correct horse battery',
    password2: 'correct horse battery',
  });
  assert.equal(res.status, 303, await textOf(res));
  res = await ctx.agent.fetch('/setup/totp');
  html = await res.text();
  assert.match(html, /Manual secret/);
  const code = totpCode(getAdmin(ctx.db).totp_secret);
  res = await ctx.agent.post('/setup/totp', { _csrf: csrfOf(html), code });
  assert.equal(res.status, 303, await textOf(res));
}

async function loginWith(ctx, agent, password) {
  const html = await (await agent.fetch('/login')).text();
  return agent.post('/login', {
    _csrf: csrfOf(html),
    username: 'ada',
    password,
    totp: totpCode(getAdmin(ctx.db).totp_secret),
  });
}

async function textOf(res) {
  try { return await res.clone().text(); } catch { return ''; }
}

function uidMessage(uid, id) {
  return {
    schema: 1,
    id: id || require('crypto').randomBytes(16).toString('hex'),
    ts: 1700000000,
    device: 'entrance',
    uid,
  };
}

test('config stays on loopback and checks the keys', () => {
  assert.throws(() => loadConfig({ ...baseEnv('/tmp/door-cfg'), HOST: '0.0.0.0' }), /127\.0\.0\.1/);
  assert.throws(() => loadConfig({ ...baseEnv('/tmp/door-cfg'), SESSION_SECRET: 'short' }), /32/);
  assert.throws(() => loadConfig({ ...baseEnv('/tmp/door-cfg'), DOOR_OPEN_MS: '50' }), /DOOR_OPEN_MS/);
});

test('timezone offset, expiry, and the daily tick', () => {
  const winter = new Date('2026-11-14T06:49:00Z');
  assert.equal(currentOffsetMin('Europe/Athens', winter), 120);
  assert.equal(localDay(winter, 'Europe/Athens'), '2026-11-14');
  assert.equal(localHm(winter, 'Europe/Athens'), '08:49');
  const summer = new Date('2026-07-14T00:30:00Z');
  assert.equal(currentOffsetMin('Europe/Athens', summer), 180);
  assert.equal(expiryFromDate('2026-11-14', 'Europe/Athens'), Math.floor(Date.parse('2026-11-14T22:00:00Z') / 1000));
  assert.equal(startOfLocalDay('2026-11-14', 'Europe/Athens'), Math.floor(Date.parse('2026-11-13T22:00:00Z') / 1000));
  assert.equal(buildSchedule({ allHours: false, days: ['1', '2', '3', '4', '5'], start: '08:00', end: '20:00' }), '1-5,08:00-20:00');
  assert.equal(shouldRunDaily(null, new Date('2026-11-14T01:30:00Z'), 'Europe/Athens', '03:00'), true);
  assert.equal(shouldRunDaily('2026-11-14', new Date('2026-11-14T10:00:00Z'), 'Europe/Athens', '03:00'), false);
  assert.equal(shouldRunDaily(null, new Date('2026-11-13T22:30:00Z'), 'Europe/Athens', '03:00'), false);
});

test('backup copies the database and keeps 14 files', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'door-bak-'));
  const db = openDatabase(path.join(dir, 'door.sqlite'));
  const dest = await backupDatabase(db, path.join(dir, 'backups'));
  const copy = require('better-sqlite3')(dest, { readonly: true });
  const version = copy.prepare("SELECT value FROM settings WHERE key = 'allowlist_version'").get();
  assert.equal(version.value, '1');
  copy.close();
  db.close();
  const backups = path.join(dir, 'more');
  fs.mkdirSync(backups);
  for (let i = 0; i < 16; i += 1) fs.writeFileSync(path.join(backups, `door-${String(i).padStart(3, '0')}.sqlite`), 'x');
  pruneBackups(backups, 14);
  assert.equal(fs.readdirSync(backups).length, 14);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('setup, login, csrf, and the secure cookie flag', async () => {
  const ctx = await start();
  try {
    const home = await ctx.agent.fetch('/');
    assert.equal(home.status, 302);
    assert.equal(home.headers.get('location'), '/login');
    const health = await ctx.agent.fetch('/health');
    assert.deepEqual(await health.json(), { ok: true });

    const setup = await ctx.agent.fetch('/setup');
    const setupCookie = setup.headers.getSetCookie().join(';');
    assert.match(setupCookie, /HttpOnly/);
    assert.match(setupCookie, /SameSite=Strict/i);
    let html = await setup.text();
    let res = await ctx.agent.post('/setup', { _csrf: csrfOf(html), token: 'nope', username: 'ada', password: 'correct horse battery', password2: 'correct horse battery' });
    assert.equal(res.status, 401);

    await enroll(ctx);
    res = await ctx.agent.fetch('/');
    assert.equal(res.status, 200);
    const live = await res.text();
    assert.match(live, /Entrance reader/);
    assert.match(live, /Open now/);

    res = await ctx.agent.post('/open', { confirm: 'yes' });
    assert.equal(res.status, 403);

    const livePage = await (await ctx.agent.fetch('/')).text();
    res = await ctx.agent.fetch('/logout', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://evil.example' },
      body: new URLSearchParams({ _csrf: csrfOf(livePage) }).toString(),
    });
    assert.equal(res.status, 403);
    assert.match(await res.text(), /Bad origin/);

    const opaque = await ctx.agent.fetch('/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null' },
      body: '_csrf=abc',
    });
    assert.match(await opaque.text(), /Invalid form token/);

    const page = await (await ctx.agent.fetch('/')).text();
    res = await ctx.agent.fetch('/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: `http://localhost:${ctx.port}`,
      },
      body: new URLSearchParams({ _csrf: csrfOf(page) }).toString(),
    });
    assert.equal(res.status, 303);
  } finally {
    await ctx.close();
  }

  const secure = await start({ env: { COOKIE_SECURE: 'true' }, config: { trustProxy: true } });
  try {
    const res = await secure.agent.fetch('/login', { headers: { 'x-forwarded-proto': 'https' } });
    const cookie = res.headers.getSetCookie().join(';');
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/i);
    assert.match(cookie, /Secure/);

    const blocked = await secure.agent.fetch('/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'https://door.example',
        'x-forwarded-proto': 'https',
      },
      body: '_csrf=abc',
    });
    assert.match(await blocked.text(), /Bad origin/);
    const forwarded = await secure.agent.fetch('/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'https://door.example',
        'x-forwarded-host': 'door.example',
        'x-forwarded-proto': 'https',
      },
      body: '_csrf=abc',
    });
    assert.match(await forwarded.text(), /Invalid form token/);
    const strayForward = await secure.agent.fetch('/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: `http://127.0.0.1:${secure.port}`,
        'x-forwarded-host': 'http://evil.example',
      },
      body: '_csrf=abc',
    });
    assert.match(await strayForward.text(), /Invalid form token/);
  } finally {
    await secure.close();
  }
});

test('login rate limit and account lockout', async () => {
  const locked = await start({ config: { loginLockoutAfter: 3 } });
  try {
    await enroll(locked);
    await locked.agent.post('/logout', { _csrf: csrfOf(await (await locked.agent.fetch('/')).text()) });
    for (let i = 0; i < 3; i += 1) {
      const page = await locked.agent.fetch('/login');
      const res = await locked.agent.post('/login', {
        _csrf: csrfOf(await page.text()),
        username: 'ada',
        password: 'wrong-password-value',
        totp: '000000',
      });
      assert.equal(res.status, 401);
    }
    const page = await locked.agent.fetch('/login');
    const res = await locked.agent.post('/login', {
      _csrf: csrfOf(await page.text()),
      username: 'ada',
      password: 'wrong-password-value',
      totp: '000000',
    });
    assert.equal(res.status, 429);
    assert.match(await res.text(), /locked/);
  } finally {
    await locked.close();
  }
});

test('a simulated read grants, denies, and syncs the allowlist', async () => {
  const clock = { t: 1700000000 };
  const ctx = await start({ now: () => clock.t });
  try {
    await enroll(ctx);
    const page = await ctx.agent.fetch('/tags');
    const html = await page.text();
    let res = await ctx.agent.post('/tags', { _csrf: csrfOf(html), uid: 'A1:B2:C3:D4', name: 'Ada' });
    assert.equal(res.status, 303);
    const allow = ctx.transport.messages.filter((item) => item.topic === 'door/reader/allowlist');
    assert.equal(allow.at(-1).opts.retain, true);
    assert.equal(allow.at(-1).opts.qos, 1);
    assert.equal(allow.at(-1).payload.entries.length, 1);
    assert.equal(allow.at(-1).payload.hash, 'hmac-sha256');

    ctx.transport.messages.length = 0;
    clock.t += 3;
    await ctx.door.handle('door/reader/uid', uidMessage('A1B2C3D4'));
    const open = ctx.transport.messages.find((item) => item.topic === 'door/actuator/open');
    const feedback = ctx.transport.messages.find((item) => item.topic === 'door/reader/feedback');
    assert.equal(open.opts.retain, false);
    assert.equal(open.payload.reason, 'tag');
    assert.equal(open.payload.duration_ms, 3000);
    assert.equal(classifyOpen({
      now: open.payload.ts,
      cmd: open.payload,
      secretHex: SECRET,
      seenNonces: new Set(),
      busy: false,
    }).reason, 'opened');
    assert.equal(feedback.payload.granted, true);
    assert.equal(feedback.payload.reason, 'ok');

    ctx.transport.messages.length = 0;
    clock.t += 3;
    await ctx.door.handle('door/reader/uid', uidMessage('DEADBEEF'));
    assert.equal(ctx.transport.messages.some((item) => item.topic === 'door/actuator/open'), false);
    const denied = ctx.transport.messages.find((item) => item.topic === 'door/reader/feedback');
    assert.equal(denied.payload.reason, 'unknown');

    const tagPage = await (await ctx.agent.fetch('/tags')).text();
    assert.match(tagPage, /DEADBEEF/);
    assert.match(tagPage, /Ada/);

    const offset = currentOffsetMin('UTC', new Date(clock.t * 1000));
    const weekday = civilFromUnix(clock.t, offset).weekday;
    const other = weekday === 1 ? 2 : 1;
    const body = new URLSearchParams();
    body.set('_csrf', csrfOf(await (await ctx.agent.fetch('/tags')).text()));
    body.set('name', 'Ada');
    body.set('enabled', '1');
    body.append('day', String(other));
    body.set('start', '00:00');
    body.set('end', '23:00');
    res = await ctx.agent.fetch('/tags/A1B2C3D4', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    assert.equal(res.status, 303);
    ctx.transport.messages.length = 0;
    clock.t += 3;
    await ctx.door.handle('door/reader/uid', uidMessage('A1B2C3D4'));
    assert.equal(ctx.transport.messages.find((item) => item.topic === 'door/reader/feedback').payload.reason, 'outside_hours');

    const disable = await ctx.agent.fetch('/tags');
    await ctx.agent.post('/tags/A1B2C3D4', { _csrf: csrfOf(await disable.text()), quick: 'disable' });
    ctx.transport.messages.length = 0;
    clock.t += 3;
    await ctx.door.handle('door/reader/uid', uidMessage('A1B2C3D4'));
    assert.equal(ctx.transport.messages.find((item) => item.topic === 'door/reader/feedback').payload.reason, 'disabled');
    assert.equal(getTag(ctx.db, 'A1B2C3D4').enabled, 0);
  } finally {
    await ctx.close();
  }
});

test('offline uploads keep their timestamps and do not open the door again', async () => {
  const ctx = await start();
  try {
    const readId = '7f3c1a0e9b2d4f6a8c0e1d2b3a495867';
    const openId = 'aa11bb22cc33dd44ee55ff6677889900';
    ctx.door.handle('door/actuator/result', {
      schema: 1, id: openId, ts: 1600000001, ok: true, reason: 'opened', duration_ms: 3000,
    });
    ctx.door.handle('door/reader/log', {
      schema: 1,
      id: 'b1041d0e0a11b1041d0e0a11b1041d0e',
      ts: 1700000000,
      entries: [{
        id: readId,
        ts: 1600000000,
        uid: 'A1B2C3D4',
        device: 'entrance',
        granted: true,
        reason: 'offline_ok',
        allowlist_version: 3,
        open_id: openId,
      }],
    });
    const row = getEvent(ctx.db, readId);
    assert.equal(row.ts, 1600000000);
    assert.equal(row.reason, 'offline_ok');
    assert.equal(row.actuator_result, 'opened');
    assert.equal(row.source, 'reader');
    ctx.door.handle('door/reader/local', {
      schema: 1, id: readId, ts: 1600000000, uid: 'A1B2C3D4', device: 'entrance',
      granted: true, reason: 'offline_ok', allowlist_version: 3, open_id: openId,
    });
    assert.equal(ctx.transport.messages.some((item) => item.topic === 'door/actuator/open'), false);
    const again = getEvent(ctx.db, readId);
    assert.equal(again.ts, 1600000000);
  } finally {
    await ctx.close();
  }
});

test('manual open is signed, and a dead broker is logged as not actuated', async () => {
  const clock = { t: 1700000000 };
  const ctx = await start({ now: () => clock.t });
  try {
    await enroll(ctx);
    clock.t += 5;
    const html = await (await ctx.agent.fetch('/')).text();
    const res = await ctx.agent.post('/open', { _csrf: csrfOf(html), confirm: 'yes' });
    assert.equal(res.status, 303);
    const open = ctx.transport.messages.find((item) => item.topic === 'door/actuator/open');
    assert.equal(open.payload.reason, 'manual');
    assert.equal(open.opts.retain, false);
    const follow = await (await ctx.agent.fetch('/')).text();
    assert.match(follow, /Manual open/);

    ctx.transport.connected = false;
    clock.t += 5;
    await assert.rejects(() => ctx.door.openNow('ada'), /broker is not connected/);
    await assert.rejects(() => ctx.door.openNow('ada'), /Wait a moment/);
    clock.t += 5;
    await assert.rejects(() => ctx.door.openNow('ada'), /broker is not connected/);
  } finally {
    await ctx.close();
  }
});

test('repeated denies and device changes notify telegram when enabled', async () => {
  const clock = { t: 1700000000 };
  const ctx = await start({
    env: { TELEGRAM_BOT_TOKEN: 'token', TELEGRAM_CHAT_ID: '42' },
    now: () => clock.t,
  });
  try {
    await ctx.door.handle('door/reader/uid', uidMessage('DEADBEEF'));
    clock.t += 3;
    await ctx.door.handle('door/reader/uid', uidMessage('DEADBEEF'));
    clock.t += 3;
    await ctx.door.handle('door/reader/uid', uidMessage('DEADBEEF'));
    assert.ok(ctx.sent.some((item) => item.text.includes('Unknown tag DEADBEEF')));
    assert.ok(ctx.sent.some((item) => item.text.includes('denied')));

    ctx.door.handle('door/reader/status', {
      schema: 1, id: '11111111111111111111111111111111', online: true, ts: clock.t,
      fw: '0.1.0', uptime_s: 5, ip: '192.168.1.40', rssi: -60, ntp: true, allowlist_version: 1, log_queued: 0,
    });
    assert.equal(ctx.sent.some((item) => item.text.includes('Entrance reader is online')), false);
    ctx.door.handle('door/reader/status', { online: false, reason: 'lwt' });
    assert.ok(ctx.sent.some((item) => item.text.includes('Entrance reader is offline')));

    updateDevice(ctx.db, 'actuator', { online: true, lastSeen: clock.t - 120, payload: '{"online":true}' });
    ctx.door.sweep();
    assert.ok(ctx.sent.some((item) => item.text.includes('Door relay is offline')));
  } finally {
    await ctx.close();
  }
});

test('the log filters, paginates, and exports csv', async () => {
  const ctx = await start();
  try {
    await enroll(ctx);
    for (let i = 0; i < 51; i += 1) {
      await ctx.door.handle('door/reader/uid', uidMessage(i.toString(16).toUpperCase().padStart(8, '0')));
    }
    await ctx.door.handle('door/reader/uid', uidMessage('A1B2C3D4'));
    const page = await (await ctx.agent.fetch('/log?page=2')).text();
    assert.match(page, /Page 2 of 2/);
    const csvRes = await ctx.agent.fetch('/log.csv?granted=0');
    assert.match(csvRes.headers.get('content-type'), /text\/csv/);
    const csv = await csvRes.text();
    assert.match(csv, /timestamp,uid,owner,granted,reason/);
    assert.equal(csv.trim().split('\n').length, 53);
  } finally {
    await ctx.close();
  }
});

test('password change and recovery', async () => {
  const ctx = await start();
  try {
    const early = await ctx.agent.fetch('/recover');
    assert.equal(early.status, 302);
    assert.equal(early.headers.get('location'), '/setup');

    await enroll(ctx);
    const other = new Agent(ctx.agent.base);
    let res = await other.post('/login', {
      _csrf: csrfOf(await (await other.fetch('/login')).text()),
      username: 'ada',
      password: 'correct horse battery',
      totp: totpCode(getAdmin(ctx.db).totp_secret),
    });
    assert.equal(res.status, 303);

    let html = await (await ctx.agent.fetch('/settings')).text();
    assert.match(html, /Change password/);
    assert.match(html, /Signed in as ada/);
    const csrf = csrfOf(html);
    res = await ctx.agent.post('/settings/password', {
      _csrf: csrf,
      current: 'wrong-password-value',
      password: 'another correct horse',
      password2: 'another correct horse',
      totp: totpCode(getAdmin(ctx.db).totp_secret),
    });
    assert.equal(res.status, 401);
    assert.match(await res.text(), /not accepted/);

    res = await ctx.agent.post('/settings/password', {
      _csrf: csrf,
      current: 'correct horse battery',
      password: 'another correct horse',
      password2: 'different correct horse',
      totp: totpCode(getAdmin(ctx.db).totp_secret),
    });
    assert.equal(res.status, 401);
    assert.match(await res.text(), /do not match/);

    res = await ctx.agent.post('/settings/password', {
      _csrf: csrf,
      current: 'correct horse battery',
      password: 'another correct horse',
      password2: 'another correct horse',
      totp: totpCode(getAdmin(ctx.db).totp_secret),
    });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), '/settings');
    const settings = await (await ctx.agent.fetch('/settings')).text();
    assert.match(settings, /Password updated/);
    const signedOut = await other.fetch('/');
    assert.equal(signedOut.status, 302);
    assert.equal(signedOut.headers.get('location'), '/login');

    res = await loginWith(ctx, new Agent(ctx.agent.base), 'correct horse battery');
    assert.equal(res.status, 401);
    res = await loginWith(ctx, new Agent(ctx.agent.base), 'another correct horse');
    assert.equal(res.status, 303);

    ctx.db.prepare('UPDATE admin SET failed_logins = 9, locked_until = ? WHERE id = 1')
      .run(Math.floor(Date.now() / 1000) + 3600);
    const guest = new Agent(ctx.agent.base);
    html = await (await guest.fetch('/recover')).text();
    assert.match(html, /authenticator code/);
    assert.doesNotMatch(html, /Recovery token/);
    const recoverCsrf = csrfOf(html);
    res = await guest.post('/recover', {
      _csrf: recoverCsrf,
      password: 'third correct horse',
      password2: 'third correct horse',
      totp: '000000',
    });
    assert.equal(res.status, 401);
    assert.match(await res.text(), /not accepted/);

    res = await guest.post('/recover', {
      _csrf: recoverCsrf,
      password: 'third correct horse',
      password2: 'third correct horse',
      totp: totpCode(getAdmin(ctx.db).totp_secret),
    });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), '/login?reset=1');
    assert.equal(getAdmin(ctx.db).locked_until, null);
    const home = await ctx.agent.fetch('/');
    assert.equal(home.status, 302);

    const loginPage = await (await guest.fetch('/login?reset=1')).text();
    assert.match(loginPage, /Password updated/);
    assert.match(loginPage, /Forgot the password/);
    res = await guest.post('/login', {
      _csrf: csrfOf(loginPage),
      username: 'ada',
      password: 'third correct horse',
      totp: totpCode(getAdmin(ctx.db).totp_secret),
    });
    assert.equal(res.status, 303);
  } finally {
    await ctx.close();
  }
});

test('reader wifi can be replaced or reset from settings', async () => {
  const ctx = await start();
  try {
    await enroll(ctx);
    const status = {
      schema: 1,
      id: '11111111111111111111111111111111',
      online: true,
      ts: Math.floor(Date.now() / 1000),
      fw: '0.1.0',
      uptime_s: 5,
      ip: '192.168.2.40',
      rssi: -60,
      ntp: true,
      allowlist_version: 1,
      log_queued: 0,
      ssid: 'Old Network',
    };
    ctx.door.handle('door/reader/status', status);
    let html = await (await ctx.agent.fetch('/settings')).text();
    assert.match(html, /Old Network/);
    assert.match(html, /Reader Wi-Fi/);
    let csrf = csrfOf(html);
    let res = await ctx.agent.post('/settings/wifi', {
      _csrf: csrf,
      ssid: 'New Network',
      password: 'correct horse',
    });
    assert.equal(res.status, 409);
    assert.match(await res.text(), /Reflash the reader/);
    assert.equal(ctx.transport.messages.some((item) => item.topic === 'door/reader/wifi'), false);

    status.fw = '0.2.0';
    ctx.door.handle('door/reader/status', status);
    const live = await (await ctx.agent.fetch('/')).text();
    assert.match(live, /Old Network/);
    html = await (await ctx.agent.fetch('/settings')).text();
    csrf = csrfOf(html);
    res = await ctx.agent.post('/settings/wifi', {
      _csrf: csrf,
      ssid: '  New Network  ',
      password: 'short',
    });
    assert.equal(res.status, 400);
    assert.match(await res.text(), /8 to 63 characters/);

    res = await ctx.agent.post('/settings/wifi', {
      _csrf: csrf,
      ssid: '  New Network  ',
      password: 'correct horse',
    });
    assert.equal(res.status, 303);
    const sent = ctx.transport.messages.filter((item) => item.topic === 'door/reader/wifi');
    assert.equal(sent.length, 1);
    assert.equal(sent[0].payload.action, 'set');
    assert.equal(sent[0].payload.ssid, 'New Network');
    assert.equal(sent[0].payload.password, 'correct horse');
    assert.equal(sent[0].payload.schema, 1);
    assert.equal(sent[0].opts.retain, false);
    const switched = await (await ctx.agent.fetch('/settings')).text();
    assert.match(switched, /switching to New Network/);
    assert.doesNotMatch(switched, /correct horse/);

    res = await ctx.agent.post('/settings/wifi/reset', { _csrf: csrf, confirm: 'no' });
    assert.equal(res.status, 400);
    assert.match(await res.text(), /Type reset/);

    res = await ctx.agent.post('/settings/wifi/reset', { _csrf: csrf, confirm: 'reset' });
    assert.equal(res.status, 303);
    const reset = ctx.transport.messages.filter((item) => item.topic === 'door/reader/wifi').at(-1);
    assert.equal(reset.payload.action, 'forget');
    assert.match(reset.payload.setup_password, /^[A-Z2-9]{10}$/);
    assert.equal(reset.opts.retain, false);
    assert.equal(reset.payload.password, undefined);
    const shown = await (await ctx.agent.fetch('/settings')).text();
    assert.match(shown, new RegExp(reset.payload.setup_password));
    assert.match(shown, /Door-Setup/);
    assert.match(shown, /192\.168\.4\.1/);

    ctx.transport.connected = false;
    res = await ctx.agent.post('/settings/wifi', {
      _csrf: csrf,
      ssid: 'Other',
      password: 'correct horse',
    });
    assert.equal(res.status, 409);
    assert.match(await res.text(), /broker is not connected/);
  } finally {
    await ctx.close();
  }
});

test('settings can scan networks at the reader', async () => {
  const ctx = await start();
  try {
    await enroll(ctx);
    const now = Math.floor(Date.now() / 1000);
    const status = {
      schema: 1,
      id: '11111111111111111111111111111111',
      online: true,
      ts: now,
      fw: '0.2.0',
      uptime_s: 5,
      ip: '192.168.2.40',
      rssi: -60,
      ntp: true,
      allowlist_version: 1,
      log_queued: 0,
      ssid: 'Old Network',
    };
    ctx.door.handle('door/reader/status', status);
    let html = await (await ctx.agent.fetch('/settings')).text();
    assert.match(html, /Scan networks/);
    let res = await ctx.agent.post('/settings/wifi/scan', { _csrf: csrfOf(html) });
    assert.equal(res.status, 409);
    assert.match(await res.text(), /scan for networks/);

    status.fw = '0.3.0';
    status.id = '22222222222222222222222222222222';
    ctx.door.handle('door/reader/status', status);
    html = await (await ctx.agent.fetch('/settings')).text();
    const posted = ctx.agent.post('/settings/wifi/scan', { _csrf: csrfOf(html) });
    let scan;
    for (let i = 0; i < 50 && !scan; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      scan = ctx.transport.messages.find((item) => item.payload && item.payload.action === 'scan');
    }
    assert.ok(scan);
    assert.equal(scan.opts.retain, false);
    ctx.door.handle('door/reader/status', {
      ...status,
      id: '33333333333333333333333333333333',
      scan_id: scan.payload.id,
      networks: [
        { ssid: 'Home', rssi: -40, secure: true },
        { ssid: 'Cafe', rssi: -70, secure: false },
        { ssid: '', rssi: -20, secure: true },
      ],
    });
    res = await posted;
    assert.equal(res.status, 303);
    const page = await (await ctx.agent.fetch('/settings')).text();
    assert.match(page, /name="ssid" value="Home"/);
    assert.match(page, /name="ssid" value="Cafe"/);
    assert.match(page, /open/);
    assert.doesNotMatch(page, /name="ssid" value=""/);

    res = await ctx.agent.post('/settings/wifi', {
      _csrf: csrfOf(page),
      ssid: 'Home',
      password: 'correct horse',
    });
    assert.equal(res.status, 303);
    const sent = ctx.transport.messages.filter((item) => item.payload && item.payload.action === 'set').at(-1);
    assert.equal(sent.payload.ssid, 'Home');
  } finally {
    await ctx.close();
  }
});

test('settings can change how long the relay stays on', async () => {
  const clock = { t: 1700000000 };
  const ctx = await start({ now: () => clock.t });
  try {
    await enroll(ctx);
    let html = await (await ctx.agent.fetch('/settings')).text();
    assert.match(html, /name="seconds"/);
    assert.match(html, /value="3"/);

    let res = await ctx.agent.post('/settings/open', { _csrf: csrfOf(html), seconds: '0.1' });
    assert.equal(res.status, 400);
    assert.match(await res.text(), /0\.2 to 10/);

    html = await (await ctx.agent.fetch('/settings')).text();
    res = await ctx.agent.post('/settings/open', { _csrf: csrfOf(html), seconds: '4.5' });
    assert.equal(res.status, 303);
    const saved = await (await ctx.agent.fetch('/settings')).text();
    assert.match(saved, /stays on for 4\.5 seconds/);
    assert.match(saved, /value="4\.5"/);
    const allow = ctx.transport.messages.filter((item) => item.topic === 'door/reader/allowlist');
    assert.equal(allow.at(-1).payload.open_ms, 4500);

    await ctx.agent.post('/tags', {
      _csrf: csrfOf(await (await ctx.agent.fetch('/tags')).text()),
      uid: 'A1B2C3D4',
      name: 'Ada',
    });
    ctx.transport.messages.length = 0;
    clock.t += 3;
    await ctx.door.handle('door/reader/uid', uidMessage('A1B2C3D4'));
    const open = ctx.transport.messages.find((item) => item.topic === 'door/actuator/open');
    assert.equal(open.payload.duration_ms, 4500);
  } finally {
    await ctx.close();
  }
});

test('websocket snapshot requires the session', async () => {
  const ctx = await start();
  try {
    await enroll(ctx);
    const anon = new WebSocket(`ws://127.0.0.1:${ctx.port}/ws`);
    const anonClosed = once(anon, 'close');
    await anonClosed;

    const socket = new WebSocket(`ws://127.0.0.1:${ctx.port}/ws`, {
      headers: { cookie: ctx.agent.cookieHeader() },
    });
    const [raw] = await once(socket, 'message');
    const msg = JSON.parse(raw.toString());
    assert.equal(msg.type, 'snapshot');
    assert.ok(Array.isArray(msg.devices));
    socket.close();
  } finally {
    await ctx.close();
  }
});
