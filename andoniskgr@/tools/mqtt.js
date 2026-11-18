'use strict';

// Tiny MQTT 3.1.1 publisher. QoS 1, username/password, clean session.
// No extra packages, so a simulated read can run on the Pi with Node alone.

const net = require('net');
const tls = require('tls');
const fs = require('fs');

function encodeRemaining(length) {
  const bytes = [];
  let left = length;
  do {
    let byte = left % 128;
    left = Math.floor(left / 128);
    if (left > 0) byte |= 0x80;
    bytes.push(byte);
  } while (left > 0);
  return Buffer.from(bytes);
}

function mqttUtf8(value) {
  const body = Buffer.from(value, 'utf8');
  if (body.length > 65535) throw new Error('MQTT string is too long');
  const head = Buffer.alloc(2);
  head.writeUInt16BE(body.length, 0);
  return Buffer.concat([head, body]);
}

function buildConnectPacket({ clientId, username, password, keepalive = 30 }) {
  // Clean session, username, and password. No Last Will: a test tool must not
  // mark a real device offline.
  const flags = 0x02 | 0x80 | 0x40;
  const body = Buffer.concat([
    mqttUtf8('MQTT'),
    Buffer.from([0x04, flags, (keepalive >> 8) & 0xff, keepalive & 0xff]),
    mqttUtf8(clientId),
    mqttUtf8(username),
    mqttUtf8(password),
  ]);
  return Buffer.concat([Buffer.from([0x10]), encodeRemaining(body.length), body]);
}

function buildPublishPacket({ topic, payload, packetId = 1, qos = 1, retain = false }) {
  if (qos !== 0 && qos !== 1) throw new Error('only QoS 0 and 1 are supported');
  let first = 0x30;
  if (qos === 1) first |= 0x02;
  if (retain) first |= 0x01;
  const parts = [mqttUtf8(topic)];
  if (qos > 0) {
    const id = Buffer.alloc(2);
    id.writeUInt16BE(packetId & 0xffff, 0);
    parts.push(id);
  }
  parts.push(Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8'));
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([first]), encodeRemaining(body.length), body]);
}

const CONNACK_REASON = {
  0: 'accepted',
  1: 'unsupported protocol',
  2: 'client id rejected',
  3: 'broker unavailable',
  4: 'bad username or password',
  5: 'not authorized',
};

function readBytes(socket, count, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => finish(() => reject(new Error('timed out waiting for the broker'))), timeoutMs);

    function finish(settle) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
      settle();
    }
    function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= count) finish(() => resolve(buf.subarray(0, count)));
    }
    function onError(err) {
      finish(() => reject(err));
    }
    function onClose() {
      finish(() => {
        reject(new Error('broker closed the connection (denied by the ACL, or the session dropped)'));
      });
    }
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

function openSocket({ host, port, useTls, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const options = { host, port };
    if (useTls && process.env.MQTT_CA) {
      options.ca = fs.readFileSync(process.env.MQTT_CA);
    }
    const socket = useTls ? tls.connect({ ...options, servername: host }, onConnect) : net.connect(options, onConnect);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('timed out connecting to the broker'));
    }, timeoutMs);
    function onConnect() {
      clearTimeout(timer);
      resolve(socket);
    }
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function publishMqtt({
  host,
  port,
  username,
  password,
  clientId,
  topic,
  payload,
  retain = false,
  qos = 1,
  useTls = false,
  timeoutMs = 5000,
}) {
  const socket = await openSocket({ host, port, useTls, timeoutMs });
  try {
    socket.write(buildConnectPacket({ clientId, username, password, keepalive: 30 }));
    const connack = await readBytes(socket, 4, timeoutMs);
    if (connack[0] !== 0x20) throw new Error('broker did not send CONNACK');
    const code = connack[3];
    if (code !== 0) {
      throw new Error(`MQTT connect refused: ${CONNACK_REASON[code] || 'code ' + code}`);
    }
    const packet = buildPublishPacket({ topic, payload, qos, retain, packetId: 1 });
    socket.write(packet);
    if (qos === 1) {
      const puback = await readBytes(socket, 4, timeoutMs);
      if (puback[0] !== 0x40) throw new Error('broker did not acknowledge the publish');
    }
    socket.write(Buffer.from([0xe0, 0x00]));
  } finally {
    socket.end();
  }
}

function mqttConfigFromEnv() {
  const host = process.env.MQTT_HOST;
  if (!host) {
    const err = new Error('Set MQTT_HOST, MQTT_USER, and MQTT_PASS');
    err.code = 'NO_MQTT';
    throw err;
  }
  if (!process.env.MQTT_USER || process.env.MQTT_PASS == null) {
    throw new Error('Set MQTT_USER and MQTT_PASS');
  }
  return {
    host,
    port: Number(process.env.MQTT_PORT || 1883),
    username: process.env.MQTT_USER,
    password: process.env.MQTT_PASS,
    useTls: process.env.MQTT_TLS === '1',
  };
}

module.exports = {
  encodeRemaining,
  buildConnectPacket,
  buildPublishPacket,
  publishMqtt,
  mqttConfigFromEnv,
};
