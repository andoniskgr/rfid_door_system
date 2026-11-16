'use strict';

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const session = require('express-session');
const QRCode = require('qrcode');
const { WebSocketServer } = require('ws');
const { normalizeUid } = require('../../contract/policy');
const auth = require('./auth');
const dbApi = require('./db');
const { SqliteSessionStore } = require('./session-store');
const { sessionFromRequest } = require('./cookies');
const { buildSchedule, cleanName, expiryFromDate, startOfLocalDay } = require('./schedule');
const { presentEvent, presentTag, REASON_LABEL } = require('./present');
const { formatIso } = require('./timeutil');
const { TOGGLES } = require('./telegram');
const pages = require('./pages');

const PAGE_SIZE = 50;

function createApp({ db, config, door }) {
  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 'loopback');
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    next();
  });
  app.use(express.urlencoded({ extended: false, limit: '32kb' }));
  app.use(session({
    name: 'door_sid',
    secret: config.sessionSecret,
    store: new SqliteSessionStore(db),
    resave: false,
    saveUninitialized: true,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: 'strict',
      maxAge: 12 * 60 * 60 * 1000,
    },
  }));
  app.use((req, res, next) => {
    if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
    next();
  });
  app.use(express.static(path.join(__dirname, '..', 'public'), { index: false, maxAge: '1h' }));
  app.get('/favicon.ico', (req, res) => res.status(204).end());
  app.get('/health', (req, res) => res.json({ ok: true }));

  app.get('/setup', (req, res) => {
    const admin = dbApi.getAdmin(db);
    if (admin && admin.totp_confirmed) return res.redirect(req.session.totpOk ? '/' : '/login');
    if (req.session.admin && admin && !admin.totp_confirmed) return res.redirect('/setup/totp');
    res.type('html').send(pages.setupPage({
      csrf: req.session.csrf,
      mode: admin ? 'resume' : 'create',
    }));
  });

  app.post('/setup', requireCsrf, asyncRoute(async (req, res) => {
    const now = nowSec();
    const ip = clientIp(req);
    if (auth.tooMany(db, ip, 'setup', config, now)) {
      return sendSetup(req, res, 'create', 'Too many attempts. Try again in a few minutes.');
    }
    const admin = dbApi.getAdmin(db);
    if (admin) return res.redirect('/setup');
    if (!auth.setupTokenValid(db, req.body.token, now)) {
      dbApi.insertAttempt(db, { ts: now, ip, kind: 'setup', success: false });
      return sendSetup(req, res, 'create', 'The setup token is wrong or expired. Restart the server to print a new one.');
    }
    const userError = auth.checkUsername(req.body.username);
    const passError = auth.checkPasswordShape(req.body.password, req.body.password2);
    if (userError || passError) return sendSetup(req, res, 'create', userError || passError);
    await auth.createAdminAccount(db, config, { username: req.body.username, password: req.body.password });
    regenerate(req, { admin: true, adminUser: req.body.username, totpOk: false }, () => {
      res.redirect(303, '/setup/totp');
    });
  }));

  app.post('/setup/resume', requireCsrf, (req, res) => {
    const now = nowSec();
    const ip = clientIp(req);
    const admin = dbApi.getAdmin(db);
    if (!admin || admin.totp_confirmed) return res.redirect('/login');
    if (auth.tooMany(db, ip, 'setup', config, now)) {
      return sendSetup(req, res, 'resume', 'Too many attempts. Try again in a few minutes.');
    }
    if (!auth.setupTokenValid(db, req.body.token, now)) {
      dbApi.insertAttempt(db, { ts: now, ip, kind: 'setup', success: false });
      return sendSetup(req, res, 'resume', 'The enrollment token is wrong or expired.');
    }
    regenerate(req, { admin: true, adminUser: admin.username, totpOk: false }, () => {
      res.redirect(303, '/setup/totp');
    });
  });

  app.get('/setup/totp', asyncRoute(async (req, res) => {
    const admin = dbApi.getAdmin(db);
    if (!req.session.admin || !admin || admin.totp_confirmed) return res.redirect('/login');
    const totp = auth.totpForSecret(admin.totp_secret, admin.username);
    const qr = await QRCode.toDataURL(totp.toString());
    res.type('html').send(pages.totpPage({ csrf: req.session.csrf, qr, secret: admin.totp_secret }));
  }));

  app.post('/setup/totp', requireCsrf, asyncRoute(async (req, res, next) => {
    const now = nowSec();
    const ip = clientIp(req);
    const admin = dbApi.getAdmin(db);
    if (!req.session.admin || !admin || admin.totp_confirmed) return res.redirect('/login');
    if (auth.tooMany(db, ip, 'totp', config, now)) {
      return renderTotpError(req, res, admin, 'Too many attempts. Try again in a few minutes.');
    }
    if (!auth.verifyTotp(admin.totp_secret, req.body.code, admin.username)) {
      dbApi.insertAttempt(db, { ts: now, ip, kind: 'totp', success: false });
      return renderTotpError(req, res, admin, 'That code was not accepted.');
    }
    dbApi.confirmTotp(db);
    dbApi.deleteSetupToken(db);
    regenerate(req, { admin: true, adminUser: admin.username, totpOk: true }, (err) => {
      if (err) return next(err);
      res.redirect(303, '/');
    });
  }));

  app.get('/login', (req, res) => {
    if (req.session.totpOk) return res.redirect('/');
    if (req.session.admin && !dbApi.getAdmin(db)?.totp_confirmed) return res.redirect('/setup/totp');
    res.type('html').send(pages.loginPage({ csrf: req.session.csrf }));
  });

  app.post('/login', requireCsrf, asyncRoute(async (req, res) => {
    const result = await auth.authenticate(db, config, {
      username: req.body.username,
      password: req.body.password,
      totp: req.body.totp,
      ip: clientIp(req),
      nowSec: nowSec(),
    });
    if (!result.ok) {
      res.status(result.status).type('html').send(pages.loginPage({ csrf: req.session.csrf, error: result.error }));
      return;
    }
    regenerate(req, { admin: true, adminUser: result.username, totpOk: true }, () => {
      res.redirect(303, '/');
    });
  }));

  app.post('/logout', requireAdmin, requireCsrf, (req, res) => {
    req.session.destroy(() => {
      res.clearCookie('door_sid');
      res.redirect(303, '/login');
    });
  });

  app.get('/', requireAdmin, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(pages.livePage({
      csrf: req.session.csrf,
      flash: takeFlash(req),
      snapshot: door.snapshot(),
    }));
  });

  app.post('/open', requireAdmin, requireCsrf, asyncRoute(async (req, res) => {
    if (req.body.confirm !== 'yes') {
      req.session.flash = { type: 'bad', text: 'The open was not confirmed.' };
      return res.redirect(303, '/');
    }
    try {
      await door.openNow(req.session.adminUser);
      req.session.flash = { type: 'ok', text: 'Open command sent.' };
    } catch (err) {
      req.session.flash = { type: 'bad', text: err.message };
    }
    res.redirect(303, '/');
  }));

  app.get('/tags', requireAdmin, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const tags = dbApi.listTags(db).map((row) => presentTag(row, config.tz));
    const unregistered = dbApi.listUnregistered(db).map((row) => ({
      uid: row.uid,
      seen: row.seen,
      lastLabel: presentEvent({ ...row, id: '', ts: row.last_ts, granted: 0, reason: 'unknown', source: '', owner_name: '' }, config.tz).time,
    }));
    res.type('html').send(pages.tagsPage({
      csrf: req.session.csrf,
      flash: takeFlash(req),
      tags,
      unregistered,
    }));
  });

  app.post('/tags', requireAdmin, requireCsrf, asyncRoute(async (req, res) => {
    try {
      const uid = normalizeUid(req.body.uid);
      if (dbApi.getTag(db, uid)) {
        req.session.flash = { type: 'bad', text: 'That tag is already registered.' };
        return res.redirect(303, '/tags');
      }
      const ts = nowSec();
      dbApi.insertTag(db, {
        uid,
        name: cleanName(req.body.name),
        enabled: 1,
        exp: null,
        sch: null,
        created_at: ts,
        updated_at: ts,
      });
      await syncAllowlist(req, 'Tag registered. It will open the door on the next read.');
    } catch (err) {
      req.session.flash = { type: 'bad', text: err.message || 'Could not register that tag.' };
    }
    res.redirect(303, '/tags');
  }));

  app.post('/tags/:uid', requireAdmin, requireCsrf, asyncRoute(async (req, res) => {
    let uid;
    try { uid = normalizeUid(req.params.uid); } catch { return res.status(404).type('text').send('Unknown tag'); }
    const tag = dbApi.getTag(db, uid);
    if (!tag) return res.status(404).type('text').send('Unknown tag');
    try {
      if (req.body.quick === 'disable' || req.body.quick === 'enable') {
        dbApi.setTagEnabled(db, uid, req.body.quick === 'enable', nowSec());
      } else {
        dbApi.updateTag(db, uid, {
          name: cleanName(req.body.name),
          enabled: req.body.enabled === '1' ? 1 : 0,
          exp: expiryFromDate(req.body.exp, config.tz),
          sch: buildSchedule({
            allHours: req.body.all_hours === '1',
            days: req.body.day,
            start: req.body.start,
            end: req.body.end,
          }),
          updated_at: nowSec(),
        });
      }
      await syncAllowlist(req, 'Tag saved.');
    } catch (err) {
      req.session.flash = { type: 'bad', text: err.message || 'Could not save that tag.' };
    }
    res.redirect(303, '/tags');
  }));

  app.post('/tags/:uid/delete', requireAdmin, requireCsrf, asyncRoute(async (req, res) => {
    let uid;
    try { uid = normalizeUid(req.params.uid); } catch { return res.status(404).type('text').send('Unknown tag'); }
    dbApi.deleteTag(db, uid);
    await syncAllowlist(req, 'Tag deleted.');
    res.redirect(303, '/tags');
  }));

  app.get('/log', requireAdmin, (req, res) => {
    const filters = readFilters(req);
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const { total, rows } = dbApi.listEvents(db, {
      ...filters.query,
      limit: PAGE_SIZE,
      offset: (page - 1) * PAGE_SIZE,
    });
    const pagesCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(pages.logPage({
      csrf: req.session.csrf,
      flash: takeFlash(req),
      rows: rows.map((row) => presentEvent(row, config.tz)),
      filters: filters.raw,
      page: Math.min(page, pagesCount),
      pages: pagesCount,
      total,
    }));
  });

  app.get('/log.csv', requireAdmin, (req, res) => {
    const filters = readFilters(req);
    const { rows } = dbApi.listEvents(db, { ...filters.query, limit: 10000, offset: 0 });
    const header = ['timestamp', 'uid', 'owner', 'granted', 'reason', 'source', 'device', 'open_id', 'actuator_result'];
    const lines = [header.join(',')];
    for (const row of rows) {
      lines.push([
        formatIso(row.ts, config.tz),
        row.uid || '',
        row.owner_name || '',
        row.granted ? 'granted' : 'denied',
        row.reason,
        row.source,
        row.device || '',
        row.open_id || '',
        row.actuator_result || '',
      ].map(csvCell).join(','));
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="door-log.csv"');
    res.send(`\uFEFF${lines.join('\n')}\n`);
  });

  app.get('/settings', requireAdmin, (req, res) => {
    const toggles = {};
    for (const [name, key] of Object.entries(TOGGLES)) toggles[name] = dbApi.getSetting(db, key) === '1';
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(pages.settingsPage({
      csrf: req.session.csrf,
      flash: takeFlash(req),
      toggles,
      telegramConfigured: Boolean(config.telegramToken),
    }));
  });

  app.post('/settings', requireAdmin, requireCsrf, (req, res) => {
    for (const [name, key] of Object.entries(TOGGLES)) {
      dbApi.setSetting(db, key, req.body[name] === '1' ? '1' : '0');
    }
    req.session.flash = { type: 'ok', text: 'Notification settings saved.' };
    res.redirect(303, '/settings');
  });

  app.use((req, res) => res.status(404).type('text').send('Not found'));
  app.use((err, req, res, next) => {
    console.error(err);
    if (res.headersSent) return next(err);
    res.status(500).type('text').send('Something went wrong.');
  });

  function readFilters(req) {
    const reason = typeof req.query.reason === 'string' && REASON_LABEL[req.query.reason] ? req.query.reason : '';
    const from = typeof req.query.from === 'string' ? req.query.from : '';
    const to = typeof req.query.to === 'string' ? req.query.to : '';
    return {
      raw: {
        uid: typeof req.query.uid === 'string' ? req.query.uid.slice(0, 40) : '',
        granted: req.query.granted === '1' || req.query.granted === '0' ? req.query.granted : '',
        reason,
        from,
        to,
      },
      query: {
        uid: typeof req.query.uid === 'string' ? req.query.uid.slice(0, 40) : '',
        granted: req.query.granted === '1' ? 1 : req.query.granted === '0' ? 0 : null,
        reason,
        from: startOfLocalDay(from, config.tz),
        to: fromDateEnd(to),
      },
    };
  }

  function fromDateEnd(dateStr) {
    const start = startOfLocalDay(dateStr, config.tz);
    if (!Number.isInteger(start)) return null;
    return expiryFromDate(dateStr, config.tz);
  }

  async function syncAllowlist(req, okText) {
    try {
      await door.publishAllowlist();
      req.session.flash = { type: 'ok', text: okText };
    } catch (err) {
      console.error('allowlist', err.message);
      req.session.flash = {
        type: 'bad',
        text: 'Saved here. The reader has not received the new list because the broker is down.',
      };
    }
  }

  return app;
}

function attachWebSocket(server, { db, config, door, hub }) {
  const wss = new WebSocketServer({ server, path: '/ws' });
  wss.on('connection', (socket, req) => {
    const origin = req.headers.origin;
    if (origin && !socketOriginAllowed(origin, req, config.trustProxy)) {
      socket.close();
      return;
    }
    if (!sessionFromRequest(db, config, req)) {
      socket.close();
      return;
    }
    hub.add(socket);
    socket.send(JSON.stringify(door.snapshot()));
    socket.on('close', () => hub.remove(socket));
    socket.on('error', () => {});
    socket.on('message', () => {});
  });
  return wss;
}

function createHub() {
  const clients = new Set();
  return {
    add(socket) { clients.add(socket); },
    remove(socket) { clients.delete(socket); },
    broadcast(message) {
      const data = JSON.stringify(message);
      for (const socket of clients) {
        if (socket.readyState === 1) socket.send(data);
      }
    },
  };
}

function requireAdmin(req, res, next) {
  if (!req.session.admin || !req.session.totpOk) return res.redirect('/login');
  return next();
}

function requireCsrf(req, res, next) {
  if (badOrigin(req)) {
    return res.status(403).type('text').send('Bad origin. Open http://127.0.0.1:3000/setup in the address bar and submit that page.');
  }
  const sent = (req.body && req.body._csrf) || req.get('x-csrf-token') || '';
  const expected = req.session && req.session.csrf;
  if (!expected || typeof sent !== 'string' || sent.length !== expected.length) {
    return res.status(403).type('text').send('Invalid form token. Reload the page and try again.');
  }
  const a = Buffer.from(sent);
  const b = Buffer.from(expected);
  if (!crypto.timingSafeEqual(a, b)) {
    return res.status(403).type('text').send('Invalid form token. Reload the page and try again.');
  }
  return next();
}

function socketOriginAllowed(origin, req, trustProxy) {
  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  const hosts = [req.headers.host || ''];
  const remote = req.socket && req.socket.remoteAddress;
  const loopback = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
  const forwarded = req.headers['x-forwarded-host'];
  if (trustProxy && loopback && forwarded) hosts.push(String(forwarded).split(',')[0].trim());
  return hosts.some((host) => host && sameSiteHost(url, host));
}

function badOrigin(req) {
  const origin = String(req.get('origin') || '').trim();
  // Browsers set this. A page on another site cannot claim a loopback origin.
  if (!origin || origin.toLowerCase() === 'null') return false;
  let url;
  try {
    url = new URL(origin);
  } catch {
    noteOrigin(req, origin);
    return true;
  }
  if (loopbackPage(url, req)) return false;
  if (candidateHosts(req).some((host) => sameSiteHost(url, host))) return false;
  noteOrigin(req, origin);
  return true;
}

function loopbackPage(url, req) {
  if (loopbackName(url.hostname) !== 'loopback') return false;
  const port = Number(url.port || defaultPort(url.protocol));
  return port === req.socket.localPort;
}

function noteOrigin(req, origin) {
  console.error('rejected origin', JSON.stringify({
    origin,
    host: req.get('host') || '',
    forwarded: req.get('x-forwarded-host') || '',
    port: req.socket && req.socket.localPort,
  }));
}

function candidateHosts(req) {
  const hosts = [];
  const host = req.get('host');
  if (host) hosts.push(host);
  const trust = req.app.get('trust proxy fn');
  const forwarded = req.get('x-forwarded-host');
  const remote = (req.socket && req.socket.remoteAddress) || (req.connection && req.connection.remoteAddress);
  if (forwarded && typeof trust === 'function' && trust(remote, 0)) {
    hosts.push(String(forwarded).split(',')[0].trim());
  }
  return hosts;
}

function sameSiteHost(originUrl, hostHeader) {
  const presented = splitHost(hostHeader);
  if (loopbackName(originUrl.hostname) !== loopbackName(presented.name)) return false;
  const originPort = originUrl.port || defaultPort(originUrl.protocol);
  const presentedPort = presented.port || defaultPort(originUrl.protocol);
  return originPort === presentedPort;
}

function splitHost(value) {
  const raw = String(value || '').trim();
  if (raw.includes('://')) {
    try {
      const parsed = new URL(raw);
      return { name: parsed.hostname.toLowerCase(), port: parsed.port };
    } catch {
      return { name: raw.toLowerCase(), port: '' };
    }
  }
  const host = raw.toLowerCase();
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    return { name: host.slice(1, end), port: host.slice(end + 2) };
  }
  const colon = host.lastIndexOf(':');
  if (colon > -1 && /^\d+$/.test(host.slice(colon + 1))) {
    return { name: host.slice(0, colon), port: host.slice(colon + 1) };
  }
  return { name: host, port: '' };
}

function loopbackName(name) {
  const host = String(name || '').toLowerCase();
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'loopback';
  return host;
}

function defaultPort(protocol) {
  return protocol === 'https:' ? '443' : '80';
}

function regenerate(req, fields, done) {
  req.session.regenerate((err) => {
    if (err) return done(err);
    req.session.admin = fields.admin;
    req.session.adminUser = fields.adminUser;
    req.session.totpOk = fields.totpOk;
    req.session.csrf = crypto.randomBytes(32).toString('hex');
    req.session.save(done);
  });
}

function takeFlash(req) {
  const flash = req.session.flash;
  delete req.session.flash;
  return flash;
}

function sendSetup(req, res, mode, error) {
  res.status(401).type('html').send(pages.setupPage({ csrf: req.session.csrf, mode, error }));
}

async function renderTotpError(req, res, admin, error) {
  const totp = auth.totpForSecret(admin.totp_secret, admin.username);
  const qr = await QRCode.toDataURL(totp.toString());
  res.status(401).type('html').send(pages.totpPage({
    csrf: req.session.csrf, qr, secret: admin.totp_secret, error,
  }));
}

function clientIp(req) {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function csvCell(value) {
  const text = String(value ?? '');
  if (/[",\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function asyncRoute(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

module.exports = {
  createApp,
  attachWebSocket,
  createHub,
  PAGE_SIZE,
};
