'use strict';

// Publish one door/reader/uid message, as the reader would after a scan.
// Stdout is the JSON payload. With MQTT_HOST set, the message is published
// unless --dry-run is passed. Without MQTT_HOST, it only prints.

const crypto = require('crypto');
const { normalizeUid } = require('../contract/policy');
const { parseArgs, usage } = require('./args');
const { mqttConfigFromEnv, publishMqtt } = require('./mqtt');

const HELP = `
Usage:
  node tools/sim-read.js [--dry-run] [--ts <unix>] [--id <32 hex>] [--device entrance] <uid>

Prints a door/reader/uid payload. Publishes it at QoS 1 when MQTT_HOST is set,
unless --dry-run is given.

  MQTT_HOST=127.0.0.1 MQTT_USER=door-reader MQTT_PASS=secret \\
    node tools/sim-read.js A1B2C3D4

The client id is door-reader-sim, so this does not kick the Pico off the broker.
The UID may contain colons or spaces; it is normalized to uppercase hex.
`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) usage(HELP);
  const rawUid = args._[0];
  if (!rawUid) usage(HELP);

  let uid;
  try {
    uid = normalizeUid(rawUid);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

  const msg = {
    schema: 1,
    id: args.id || crypto.randomBytes(16).toString('hex'),
    ts: args.ts != null ? Number(args.ts) : Math.floor(Date.now() / 1000),
    device: args.device || 'entrance',
    uid,
  };
  if (!/^[0-9a-f]{32}$/.test(msg.id) || !Number.isInteger(msg.ts)) {
    console.error('id must be 32 lowercase hex characters and ts must be an integer');
    process.exit(1);
  }

  console.log(JSON.stringify(msg));
  if (args['dry-run'] || !process.env.MQTT_HOST) {
    if (!args['dry-run'] && !process.env.MQTT_HOST) {
      console.error('dry-run (set MQTT_HOST, MQTT_USER, and MQTT_PASS to publish)');
    }
    return;
  }

  const mqtt = mqttConfigFromEnv();
  await publishMqtt({
    ...mqtt,
    clientId: 'door-reader-sim',
    topic: 'door/reader/uid',
    payload: JSON.stringify(msg),
    retain: false,
    qos: 1,
  });
  console.error(`published door/reader/uid to ${mqtt.host}:${mqtt.port}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
