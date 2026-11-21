'use strict';

(function () {
  const devices = document.getElementById('devices');
  const body = document.getElementById('events-body');
  const mqtt = document.getElementById('mqtt');
  if (!devices || !body) return;

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[ch]));
  }

  function deviceCard(device) {
    const bits = [];
    if (device.ssid) bits.push(device.ssid);
    if (device.ip) bits.push(device.ip);
    if (device.fw) bits.push('firmware ' + device.fw);
    if (device.rssi != null) bits.push(device.rssi + ' dBm');
    if (device.allowlist != null) bits.push('allowlist ' + device.allowlist);
    if (device.relay) bits.push('relay ' + device.relay);
    if (device.logQueued) bits.push(device.logQueued + ' logs queued');
    if (device.sleeping) bits.push('asleep until a card');
    return '<article class="card"><h2>' + esc(device.title) + '</h2>'
      + '<p class="' + (device.online ? 'ok' : 'bad') + '">' + (device.online ? 'Online' : 'Offline') + '</p>'
      + '<p>Last heartbeat: ' + esc(device.lastSeen) + '</p>'
      + (bits.length ? '<p class="muted">' + esc(bits.join(' · ')) + '</p>' : '')
      + '</article>';
  }

  function eventRow(event) {
    const detail = event.actuator && event.actuator !== 'opened'
      ? event.reasonLabel + ' · ' + event.actuatorLabel
      : event.reasonLabel;
    return '<tr id="ev-' + esc(event.id) + '"><td>' + esc(event.time) + '</td><td><code>'
      + esc(event.uid) + '</code></td><td>' + esc(event.owner) + '</td><td class="'
      + (event.granted ? 'ok' : 'bad') + '">' + (event.granted ? 'Granted' : 'Denied')
      + '</td><td>' + esc(detail) + '</td></tr>';
  }

  function drawDevices(list) {
    devices.innerHTML = list.map(deviceCard).join('');
  }

  function upsert(event) {
    const html = eventRow(event);
    const existing = document.getElementById('ev-' + event.id);
    if (existing) existing.outerHTML = html;
    else body.insertAdjacentHTML('afterbegin', html);
    const empty = body.querySelector('td[colspan]');
    if (empty) empty.parentElement.remove();
  }

  function setMqtt(connected) {
    if (!mqtt) return;
    mqtt.className = connected ? 'muted' : 'flash bad';
    mqtt.textContent = connected
      ? 'Broker connected.'
      : 'Broker disconnected. The reader will decide from its cached list until the broker returns.';
  }

  let delay = 1000;
  function connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(proto + '://' + location.host + '/ws');
    socket.onopen = function () { delay = 1000; };
    socket.onmessage = function (message) {
      const data = JSON.parse(message.data);
      if (data.type === 'snapshot') {
        setMqtt(data.mqtt);
        drawDevices(data.devices);
        body.innerHTML = data.events.map(eventRow).join('') || '<tr><td colspan="5">No reads yet.</td></tr>';
      } else if (data.type === 'devices') {
        setMqtt(data.mqtt);
        drawDevices(data.devices);
      } else if (data.type === 'event') {
        upsert(data.event);
      }
    };
    socket.onclose = function () {
      setTimeout(connect, delay);
      delay = Math.min(delay * 2, 10000);
    };
  }
  connect();
}());
