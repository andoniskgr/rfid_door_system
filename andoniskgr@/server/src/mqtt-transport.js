'use strict';

const fs = require('fs');
const mqtt = require('mqtt');

const TOPICS = [
  'door/reader/uid',
  'door/reader/local',
  'door/reader/log',
  'door/reader/status',
  'door/actuator/status',
  'door/actuator/result',
];

function createMqttTransport({ config, onMessage, onConnect }) {
  const transport = { connected: false, onConnect };
  const url = `${config.mqttTls ? 'mqtts' : 'mqtt'}://${config.mqttHost}:${config.mqttPort}`;
  const options = {
    username: config.mqttUser,
    password: config.mqttPass,
    clientId: 'door-server',
    clean: true,
    keepalive: 60,
    reconnectPeriod: 2000,
    protocolVersion: 4,
    rejectUnauthorized: true,
  };
  if (config.mqttCaPath) options.ca = fs.readFileSync(config.mqttCaPath);
  const client = mqtt.connect(url, options);

  client.on('connect', () => {
    transport.connected = true;
    client.subscribe(TOPICS, { qos: 1 }, (err) => {
      if (err) console.error('mqtt subscribe', err.message);
    });
    if (transport.onConnect) {
      Promise.resolve(transport.onConnect()).catch((err) => console.error('mqtt connect hook', err.message));
    }
  });
  client.on('close', () => { transport.connected = false; });
  client.on('offline', () => { transport.connected = false; });
  client.on('error', (err) => console.error('mqtt', err.message));
  client.on('message', (topic, payload) => {
    let msg;
    try {
      msg = JSON.parse(payload.toString('utf8'));
    } catch {
      console.error('mqtt bad json on', topic);
      return;
    }
    if (!msg || typeof msg !== 'object') return;
    try {
      onMessage(topic, msg);
    } catch (err) {
      console.error('mqtt handler', err.message);
    }
  });

  transport.publish = (topic, payload, opts) => new Promise((resolve, reject) => {
    if (!client.connected) {
      reject(new Error('MQTT broker is not connected'));
      return;
    }
    client.publish(topic, payload, opts, (err) => (err ? reject(err) : resolve()));
  });
  transport.close = () => new Promise((resolve) => {
    client.end(true, {}, resolve);
  });
  return transport;
}

module.exports = { createMqttTransport, TOPICS };
