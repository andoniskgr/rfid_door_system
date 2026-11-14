'use strict';

// Build a signed door/actuator/open command. Printing does not open the door.
// Publishing requires --publish, so a normal run cannot pulse the relay.

const crypto = require('crypto');
const fs = require('fs');
const { LIMITS, signOpen, classifyOpen } = require('../contract/policy');
const { parseArgs, usage } = require('./args');
const { mqttConfigFromEnv, publishMqtt } = require('./mqtt');

const HELP = `
Usage:
  node tools/sign-open.js [--publish] [--source server|reader] [--reason tag|manual|offline]
                          [--duration 3000] [--ts <unix>] [--id <32 hex>] [--nonce <32 hex>]
                          [--secret <64 hex>] [--verify <file.json>]

Prints a signed command. The HMAC key is DOOR_HMAC_SECRET or --secret
(64 hex characters, 32 raw bytes, not the ASCII of the hex text).

  DOOR_HMAC_SECRET=$(openssl rand -hex 32) node tools/sign-open.js --reason manual

Publish only when you mean it. With a live ESP-01 this pulses the relay:

  DOOR_HMAC_SECRET=... MQTT_HOST=127.0.0.1 MQTT_USER=door-server MQTT_PASS=... \\
    node tools/sign-open.js --publish --source server --reason manual

Check a saved command against the key:

  DOOR_HMAC_SECRET=... node tools/sign-open.js --verify contract/examples/open.json
`;

function hex32(value, label) {
  const hex = value || crypto.randomBytes(16).toString('hex');
  if (!/^[0-9a-f]{32}$/.test(hex)) {
    throw new Error(`${label} must be 32 lowercase hex characters`);
  }
  return hex;
}

function loadSecret(args) {
  const secret = args.secret || process.env.DOOR_HMAC_SECRET;
  if (!secret) throw new Error('Set DOOR_HMAC_SECRET or pass --secret <64 hex>');
  return secret.trim();
}

async function verify(args) {
  const secret = loadSecret(args);
  const file = args.verify;
  if (typeof file !== 'string') throw new Error('--verify needs a JSON file');
  const cmd = JSON.parse(fs.readFileSync(file, 'utf8'));
  const result = classifyOpen({
    now: cmd.ts,
    cmd,
    secretHex: secret,
    seenNonces: new Set(),
    busy: false,
  });
  if (!result.ok) {
    console.error(`rejected: ${result.reason}`);
    process.exit(1);
  }
  console.log(`valid ${file}: ${result.reason} for ${cmd.duration_ms} ms`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) usage(HELP);
  if (args.verify) {
    await verify(args);
    return;
  }

  const source = args.source || 'server';
  const reason = args.reason || 'manual';
  const duration = args.duration != null ? Number(args.duration) : LIMITS.OPEN_DEFAULT_MS;
  if (!Number.isInteger(duration) || duration < LIMITS.OPEN_MIN_MS || duration > LIMITS.OPEN_MAX_MS) {
    throw new Error(`duration must be an integer from ${LIMITS.OPEN_MIN_MS} to ${LIMITS.OPEN_MAX_MS}`);
  }
  const cmd = signOpen(loadSecret(args), {
    id: hex32(args.id, 'id'),
    ts: args.ts != null ? Number(args.ts) : Math.floor(Date.now() / 1000),
    nonce: hex32(args.nonce, 'nonce'),
    duration_ms: duration,
    source,
    reason,
  });
  if (!Number.isInteger(cmd.ts)) throw new Error('ts must be an integer');

  console.log(JSON.stringify(cmd));
  if (!args.publish) {
    console.error('not published (pass --publish to send door/actuator/open)');
    return;
  }

  const mqtt = mqttConfigFromEnv();
  const clientId = source === 'reader' ? 'door-reader-sim' : 'door-server-sim';
  await publishMqtt({
    ...mqtt,
    clientId,
    topic: 'door/actuator/open',
    payload: JSON.stringify(cmd),
    retain: false,
    qos: 1,
  });
  console.error(`published door/actuator/open to ${mqtt.host}:${mqtt.port} as ${mqtt.username}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
