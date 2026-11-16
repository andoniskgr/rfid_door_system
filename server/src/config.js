'use strict';

const path = require('path');
const { decodeKey, LIMITS } = require('../../contract/policy');

function loadConfig(env = process.env) {
  const missing = ['SESSION_SECRET', 'MQTT_HOST', 'MQTT_USER', 'MQTT_PASS', 'DOOR_HMAC_SECRET', 'ALLOWLIST_HMAC_KEY']
    .filter((name) => !env[name]);
  if (missing.length) {
    throw new Error(`Missing ${missing.join(', ')}`);
  }
  if (String(env.SESSION_SECRET).length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters');
  }

  const host = env.HOST || '127.0.0.1';
  if (host !== '127.0.0.1' && host !== 'localhost') {
    throw new Error('HOST must be 127.0.0.1. Reach the app through Tailscale Serve.');
  }

  decodeKey(env.DOOR_HMAC_SECRET.trim());
  decodeKey(env.ALLOWLIST_HMAC_KEY.trim());

  const openMs = env.DOOR_OPEN_MS == null || env.DOOR_OPEN_MS === ''
    ? LIMITS.OPEN_DEFAULT_MS
    : Number(env.DOOR_OPEN_MS);
  if (!Number.isInteger(openMs) || openMs < LIMITS.OPEN_MIN_MS || openMs > LIMITS.OPEN_MAX_MS) {
    throw new Error(`DOOR_OPEN_MS must be an integer from ${LIMITS.OPEN_MIN_MS} to ${LIMITS.OPEN_MAX_MS}`);
  }

  const tz = env.TZ || 'UTC';
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz }).format(new Date());
  } catch {
    throw new Error(`TZ is not a valid timezone: ${tz}`);
  }

  const port = Number(env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT is invalid');

  const dataDir = path.resolve(env.DATA_DIR || path.join(__dirname, '..', 'data'));
  const token = env.TELEGRAM_BOT_TOKEN || '';
  const chat = env.TELEGRAM_CHAT_ID || '';

  return {
    host,
    port,
    cookieSecure: env.COOKIE_SECURE !== 'false',
    trustProxy: env.TRUST_PROXY === 'true' || env.TRUST_PROXY === '1',
    sessionSecret: env.SESSION_SECRET,
    tz,
    dataDir,
    dbPath: path.join(dataDir, 'door.sqlite'),
    backupDir: path.join(dataDir, 'backups'),
    mqttHost: env.MQTT_HOST,
    mqttPort: Number(env.MQTT_PORT || 1883),
    mqttUser: env.MQTT_USER,
    mqttPass: env.MQTT_PASS,
    mqttTls: env.MQTT_TLS === '1',
    mqttCaPath: env.MQTT_CA || '',
    openSecret: env.DOOR_HMAC_SECRET.trim(),
    allowlistKey: env.ALLOWLIST_HMAC_KEY.trim(),
    openMs,
    telegramToken: token && chat ? token : '',
    telegramChat: token && chat ? chat : '',
    loginIpLimit: 5,
    loginIpWindowSec: 15 * 60,
    loginLockoutAfter: 10,
    loginLockoutSec: 15 * 60,
    setupTtlSec: 30 * 60,
    // OWASP argon2id baseline. Tests pass a lighter argon via config override.
    argon: { memoryCost: 19456, timeCost: 2, parallelism: 1 },
  };
}

module.exports = { loadConfig };
