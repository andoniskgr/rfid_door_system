'use strict';

const http = require('http');
const { loadConfig, loadEnvFile } = require('./config');
const { openDatabase, getAdmin, getSetting, setSetting, pruneAttempts } = require('./db');
const { issueSetupToken } = require('./auth');
const { createTelegram } = require('./telegram');
const { createDoor } = require('./door');
const { createMqttTransport } = require('./mqtt-transport');
const { createApp, attachWebSocket, createHub } = require('./app');
const { backupDatabase } = require('./backup');
const { localDay, shouldRunDaily } = require('./timeutil');

function main() {
  loadEnvFile();
  const config = loadConfig();
  const db = openDatabase(config.dbPath);
  const hub = createHub();
  const telegram = createTelegram({ config, db });
  const hooks = {};
  const transport = createMqttTransport({
    config,
    onMessage: (topic, msg) => hooks.door.handle(topic, msg),
    onConnect: () => hooks.door.publishAllowlist().catch((err) => console.error('allowlist', err.message)),
  });
  hooks.door = createDoor({ db, config, transport, telegram, hub });
  const door = hooks.door;

  const admin = getAdmin(db);
  if (!admin || !admin.totp_confirmed) {
    const token = issueSetupToken(db, Math.floor(Date.now() / 1000), config.setupTtlSec);
    const label = admin ? 'enrollment' : 'setup';
    console.log(`door-access ${label} token (valid 30 minutes): ${token}`);
  }

  const app = createApp({ db, config, door });
  const server = http.createServer(app);
  attachWebSocket(server, { db, config, door, hub });

  const timer = setInterval(() => tick(db, config, door), 15 * 1000);
  timer.unref();

  server.listen(config.port, config.host, () => {
    console.log(`door-access listening on http://${config.host}:${config.port}`);
  });

  function shutdown() {
    clearInterval(timer);
    server.close(() => {
      transport.close().finally(() => {
        db.close();
        process.exit(0);
      });
    });
    setTimeout(() => process.exit(0), 2000).unref();
  }
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

function tick(db, config, door) {
  try {
    const now = new Date();
    const lastBackup = getSetting(db, 'last_backup_day');
    if (shouldRunDaily(lastBackup, now, config.tz, '03:00')) {
      const day = localDay(now, config.tz);
      backupDatabase(db, config.backupDir).then(() => {
        setSetting(db, 'last_backup_day', day);
        console.log('database backup written');
      }).catch((err) => console.error('backup', err.message));
    }
    const lastSync = getSetting(db, 'last_allowlist_day');
    if (shouldRunDaily(lastSync, now, config.tz, '03:05')) {
      door.publishAllowlist().then(() => {
        setSetting(db, 'last_allowlist_day', localDay(new Date(), config.tz));
      }).catch((err) => console.error('allowlist', err.message));
    }
    door.sweep();
    pruneAttempts(db, Math.floor(Date.now() / 1000) - 2 * 24 * 60 * 60);
  } catch (err) {
    console.error('tick', err.message);
  }
}

if (require.main === module) main();

module.exports = { main, tick };
