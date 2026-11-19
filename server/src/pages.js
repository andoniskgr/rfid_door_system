'use strict';

const { DAY_NAMES } = require('./schedule');
const { REASON_LABEL } = require('./present');

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function layout({ title, body, csrf, user, flash }) {
  const nav = user ? `
    <nav>
      <a href="/">Live</a>
      <a href="/tags">Tags</a>
      <a href="/log">Log</a>
      <a href="/settings">Settings</a>
      <form method="post" action="/logout">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        <button type="submit">Log out</button>
      </form>
    </nav>` : '';
  const banner = flash ? `<p class="flash ${esc(flash.type || '')}" role="status">${esc(flash.text)}</p>` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <title>${esc(title)} · Door access</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <header>
    <a class="brand" href="/">Door access</a>
    ${nav}
  </header>
  <main>
    ${banner}
    ${body}
  </main>
</body>
</html>`;
}

function field(label, inner) {
  return `<label class="field"><span>${label}</span>${inner}</label>`;
}

function loginPage({ csrf, error, notice }) {
  return layout({
    title: 'Log in',
    csrf,
    body: `<h1>Log in</h1>
      ${notice ? `<p class="flash ok">${esc(notice)}</p>` : ''}
      ${error ? `<p class="flash bad">${esc(error)}</p>` : ''}
      <form method="post" action="/login" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${field('Username', '<input name="username" autocomplete="username" required>')}
        ${field('Password', '<input name="password" type="password" autocomplete="current-password" required>')}
        ${field('Authentication code', '<input name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required>')}
        <button type="submit">Log in</button>
      </form>
      <p class="muted"><a href="/recover">Forgot the password?</a></p>`,
  });
}

function recoverPage({ csrf, error }) {
  return layout({
    title: 'Recover password',
    csrf,
    body: `<h1>Recover the password</h1>
      <p>Enter a new password and the authenticator code. Every session is signed out.</p>
      ${error ? `<p class="flash bad">${esc(error)}</p>` : ''}
      <form method="post" action="/recover" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${field('New password', '<input name="password" type="password" autocomplete="new-password" required minlength="12">')}
        ${field('New password again', '<input name="password2" type="password" autocomplete="new-password" required minlength="12">')}
        ${field('Authentication code', '<input name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required>')}
        <button type="submit">Set a new password</button>
      </form>
      <p class="muted"><a href="/login">Back to log in</a></p>`,
  });
}

function setupPage({ csrf, mode, error }) {
  const create = mode === 'create';
  const form = create ? `
    <p>Create the only admin account. The setup token was printed in the server log.</p>
    <form method="post" action="/setup" class="stack">
      <input type="hidden" name="_csrf" value="${esc(csrf)}">
      ${field('Setup token', '<input name="token" autocomplete="off" required>')}
      ${field('Username', '<input name="username" autocomplete="username" required>')}
      ${field('Password', '<input name="password" type="password" autocomplete="new-password" required minlength="12">')}
      ${field('Password again', '<input name="password2" type="password" autocomplete="new-password" required minlength="12">')}
      <button type="submit">Create account</button>
    </form>` : `
    <p>This account still needs an authenticator code. Enter the enrollment token from the server log.</p>
    <form method="post" action="/setup/resume" class="stack">
      <input type="hidden" name="_csrf" value="${esc(csrf)}">
      ${field('Enrollment token', '<input name="token" autocomplete="off" required>')}
      <button type="submit">Continue</button>
    </form>`;
  return layout({
    title: 'Set up',
    csrf,
    body: `<h1>Set up</h1>${error ? `<p class="flash bad">${esc(error)}</p>` : ''}${form}`,
  });
}

function totpPage({ csrf, qr, secret, error }) {
  return layout({
    title: 'Authenticator',
    csrf,
    body: `<h1>Authenticator</h1>
      <p>Add this account to your authenticator app, then enter the 6-digit code.</p>
      ${error ? `<p class="flash bad">${esc(error)}</p>` : ''}
      <img class="qr" alt="QR code for the authenticator app" src="${esc(qr)}">
      <p class="secret">Manual secret: <code>${esc(secret)}</code></p>
      <form method="post" action="/setup/totp" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${field('Authentication code', '<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required>')}
        <button type="submit">Confirm</button>
      </form>`,
  });
}

function deviceCard(device) {
  const bits = [];
  if (device.ssid) bits.push(device.ssid);
  if (device.ip) bits.push(device.ip);
  if (device.fw) bits.push(`firmware ${device.fw}`);
  if (device.rssi != null) bits.push(`${device.rssi} dBm`);
  if (device.allowlist != null) bits.push(`allowlist ${device.allowlist}`);
  if (device.relay) bits.push(`relay ${device.relay}`);
  if (device.logQueued) bits.push(`${device.logQueued} logs queued`);
  return `<article class="card">
    <h2>${esc(device.title)}</h2>
    <p class="${device.online ? 'ok' : 'bad'}">${device.online ? 'Online' : 'Offline'}</p>
    <p>Last heartbeat: ${esc(device.lastSeen)}</p>
    ${bits.length ? `<p class="muted">${esc(bits.join(' · '))}</p>` : ''}
  </article>`;
}

function eventRow(event) {
  const result = event.granted ? 'Granted' : 'Denied';
  const detail = event.actuator && event.actuator !== 'opened'
    ? `${event.reasonLabel} · ${event.actuatorLabel}`
    : event.reasonLabel;
  return `<tr id="ev-${esc(event.id)}">
    <td>${esc(event.time)}</td>
    <td><code>${esc(event.uid)}</code></td>
    <td>${esc(event.owner)}</td>
    <td class="${event.granted ? 'ok' : 'bad'}">${result}</td>
    <td>${esc(detail)}</td>
  </tr>`;
}

function livePage({ csrf, flash, snapshot }) {
  const mqtt = snapshot.mqtt
    ? ''
    : '<p id="mqtt" class="flash bad">Broker disconnected. The reader will decide from its cached list until the broker returns.</p>';
  return layout({
    title: 'Live',
    csrf,
    user: true,
    flash,
    body: `<h1>Live</h1>
      ${mqtt || '<p id="mqtt" class="muted">Broker connected.</p>'}
      <section id="devices" class="cards">${snapshot.devices.map(deviceCard).join('')}</section>
      <form method="post" action="/open" class="open-form" onsubmit="return confirm('Open the door now?')">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        <input type="hidden" name="confirm" value="yes">
        <button type="submit">Open now</button>
      </form>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>UID</th><th>Name</th><th>Result</th><th>Detail</th></tr></thead>
          <tbody id="events-body">${snapshot.events.map(eventRow).join('') || '<tr><td colspan="5">No reads yet.</td></tr>'}</tbody>
        </table>
      </div>
      <script src="/app.js"></script>`,
  });
}

function dayBoxes(selected) {
  return DAY_NAMES.map((name, index) => {
    const day = index + 1;
    const on = selected.includes(day) ? ' checked' : '';
    return `<label class="check"><input type="checkbox" name="day" value="${day}"${on}> ${name}</label>`;
  }).join('');
}

function tagEditor(tag, csrf) {
  const schedule = tag.schedule || { allHours: true, days: [], start: '', end: '' };
  return `<details>
    <summary>Edit</summary>
    <form method="post" action="/tags/${esc(tag.uid)}" class="stack">
      <input type="hidden" name="_csrf" value="${esc(csrf)}">
      ${field('Name', `<input name="name" maxlength="80" value="${esc(tag.name)}" required>`)}
      <label class="check"><input type="checkbox" name="enabled" value="1"${tag.enabled ? ' checked' : ''}> Enabled</label>
      ${field('Valid through', `<input name="exp" type="date" value="${esc(tag.exp)}">`)}
      <label class="check"><input type="checkbox" name="all_hours" value="1"${schedule.allHours ? ' checked' : ''}> All hours</label>
      <div class="days">${dayBoxes(schedule.days || [])}</div>
      ${field('From', `<input name="start" type="time" value="${esc(schedule.start || '')}">`)}
      ${field('Until', `<input name="end" type="time" value="${esc(schedule.end || '')}">`)}
      <button type="submit">Save</button>
    </form>
  </details>`;
}

function tagsPage({ csrf, flash, tags, unregistered }) {
  const unknown = unregistered.length ? `
    <h2>Unregistered</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>UID</th><th>Last seen</th><th>Times</th><th></th></tr></thead>
      <tbody>
        ${unregistered.map((row) => `<tr>
          <td><code>${esc(row.uid)}</code></td>
          <td>${esc(row.lastLabel)}</td>
          <td>${esc(row.seen)}</td>
          <td>
            <form method="post" action="/tags" class="inline">
              <input type="hidden" name="_csrf" value="${esc(csrf)}">
              <input type="hidden" name="uid" value="${esc(row.uid)}">
              <input name="name" maxlength="80" placeholder="Name" aria-label="Name for ${esc(row.uid)}">
              <button type="submit">Register</button>
            </form>
          </td>
        </tr>`).join('')}
      </tbody>
    </table></div>` : '';
  const rows = tags.map((tag) => `<tr>
    <td><code>${esc(tag.uid)}</code></td>
    <td>${esc(tag.name)}</td>
    <td class="${tag.enabled ? 'ok' : 'bad'}">${tag.enabled ? 'Enabled' : 'Disabled'}</td>
    <td>${esc(tag.exp || 'None')}</td>
    <td>${esc(tag.sch || 'All hours')}</td>
    <td class="actions">
      <form method="post" action="/tags/${esc(tag.uid)}" class="inline">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        <input type="hidden" name="quick" value="${tag.enabled ? 'disable' : 'enable'}">
        <button type="submit">${tag.enabled ? 'Disable' : 'Enable'}</button>
      </form>
      <form method="post" action="/tags/${esc(tag.uid)}/delete" class="inline" onsubmit="return confirm('Delete this tag? It will stop opening the door.')">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        <button type="submit">Delete</button>
      </form>
      ${tagEditor(tag, csrf)}
    </td>
  </tr>`).join('');
  return layout({
    title: 'Tags',
    csrf,
    user: true,
    flash,
    body: `<h1>Tags</h1>
      <p class="muted">A matching UID opens the door. MIFARE UIDs can be copied, so disable a tag that you cannot account for.</p>
      ${unknown}
      <h2>Registered</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>UID</th><th>Name</th><th>Status</th><th>Valid through</th><th>Hours</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6">No tags yet.</td></tr>'}</tbody>
      </table></div>
      <h2>Add a tag</h2>
      <form method="post" action="/tags" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${field('UID', '<input name="uid" required pattern="[0-9A-Fa-f: ]{8,32}" autocomplete="off">')}
        ${field('Name', '<input name="name" maxlength="80" required>')}
        <button type="submit">Add</button>
      </form>`,
  });
}

function logPage({ csrf, flash, rows, filters, page, pages, total }) {
  const query = (extra) => {
    const params = new URLSearchParams();
    if (filters.uid) params.set('uid', filters.uid);
    if (filters.granted === '0' || filters.granted === '1') params.set('granted', filters.granted);
    if (filters.reason) params.set('reason', filters.reason);
    if (filters.from) params.set('from', filters.from);
    if (filters.to) params.set('to', filters.to);
    if (extra) Object.entries(extra).forEach(([key, value]) => params.set(key, value));
    const text = params.toString();
    return text ? `?${text}` : '';
  };
  const options = ['', ...Object.keys(REASON_LABEL)].map((reason) => {
    const label = reason ? REASON_LABEL[reason] : 'Any reason';
    const selected = filters.reason === reason ? ' selected' : '';
    return `<option value="${esc(reason)}"${selected}>${esc(label)}</option>`;
  }).join('');
  const granted = (value, label) => `<option value="${value}"${filters.granted === value ? ' selected' : ''}>${label}</option>`;
  return layout({
    title: 'Log',
    csrf,
    user: true,
    flash,
    body: `<h1>Log</h1>
      <form method="get" action="/log" class="filters">
        ${field('UID', `<input name="uid" value="${esc(filters.uid)}">`)}
        ${field('Result', `<select name="granted">${granted('', 'Any')}${granted('1', 'Granted')}${granted('0', 'Denied')}</select>`)}
        ${field('Reason', `<select name="reason">${options}</select>`)}
        ${field('From', `<input name="from" type="date" value="${esc(filters.from)}">`)}
        ${field('To', `<input name="to" type="date" value="${esc(filters.to)}">`)}
        <button type="submit">Filter</button>
        <a href="/log.csv${query()}">Download CSV</a>
      </form>
      <p class="muted">${total} events</p>
      <div class="table-wrap"><table>
        <thead><tr><th>Time</th><th>UID</th><th>Name</th><th>Result</th><th>Detail</th><th>Source</th></tr></thead>
        <tbody>
          ${rows.map((event) => `<tr>
            <td>${esc(event.time)}</td>
            <td><code>${esc(event.uid)}</code></td>
            <td>${esc(event.owner)}</td>
            <td class="${event.granted ? 'ok' : 'bad'}">${event.granted ? 'Granted' : 'Denied'}</td>
            <td>${esc(event.reasonLabel)}</td>
            <td>${esc(event.source)}</td>
          </tr>`).join('') || '<tr><td colspan="6">No events.</td></tr>'}
        </tbody>
      </table></div>
      <p class="pager">
        ${page > 1 ? `<a href="/log${query({ page: String(page - 1) })}">Previous</a>` : ''}
        <span>Page ${page} of ${pages}</span>
        ${page < pages ? `<a href="/log${query({ page: String(page + 1) })}">Next</a>` : ''}
      </p>`,
  });
}

function networkChoices(networks) {
  if (!networks.length) return '<p class="muted">Scan to list the networks the reader can see.</p>';
  return networks.map((item) => {
    let label = item.ssid;
    if (item.rssi != null) label += ` (${item.rssi} dBm${item.secure ? '' : ', open'})`;
    return `<label class="check"><input type="radio" name="ssid" value="${esc(item.ssid)}"> ${esc(label)}</label>`;
  }).join('');
}

function settingsPage({ csrf, flash, toggles, telegramConfigured, username, passwordError, doorError, openSeconds, wifiError, reader, networks = [] }) {
  let where = 'The reader is offline.';
  if (reader.online && reader.ssid) {
    where = `The reader is on ${reader.ssid}${reader.ip ? ` at ${reader.ip}` : ''}.`;
  } else if (reader.online) {
    where = 'The reader is online and has not reported a network yet.';
  } else if (reader.ssid) {
    where = `The reader is offline. Last network was ${reader.ssid}.`;
  }
  const box = (name, label) => `<label class="check"><input type="checkbox" name="${name}" value="1"${toggles[name] ? ' checked' : ''}> ${label}</label>`;
  return layout({
    title: 'Settings',
    csrf,
    user: true,
    flash,
    body: `<h1>Settings</h1>
      <p class="muted">${telegramConfigured ? 'Telegram is configured.' : 'Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to send messages.'}</p>
      <form method="post" action="/settings" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${box('unknown', 'Unknown tag')}
        ${box('denied', 'Repeated denied attempts')}
        ${box('device', 'Device online or offline')}
        ${box('manual', 'Manual open')}
        <button type="submit">Save</button>
      </form>
      <h2>Door</h2>
      <p class="muted">How long the relay stays on after a granted tag or Open now. From 0.2 to 10 seconds. An offline grant on the reader uses the same time after the next allowlist update.</p>
      ${doorError ? `<p class="flash bad">${esc(doorError)}</p>` : ''}
      <form method="post" action="/settings/open" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${field('Open time (seconds)', `<input name="seconds" type="number" min="0.2" max="10" step="0.1" inputmode="decimal" required value="${esc(openSeconds)}">`)}
        <button type="submit">Save open time</button>
      </form>
      <h2>Reader Wi-Fi</h2>
      <p class="muted">${esc(where)} Scan lists the networks at the door. Choose one and enter its password. A wrong password leaves the reader on the current network. Reset clears the saved network and starts Door-Setup for 10 minutes.</p>
      ${wifiError ? `<p class="flash bad">${esc(wifiError)}</p>` : ''}
      <form method="post" action="/settings/wifi/scan" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        <button type="submit">Scan networks</button>
      </form>
      <form method="post" action="/settings/wifi" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${networkChoices(networks)}
        ${field('Hidden network', '<input name="other" maxlength="32" autocomplete="off">')}
        ${field('Password', '<input name="password" type="password" maxlength="63" autocomplete="new-password">')}
        <button type="submit">Save network</button>
      </form>
      <form method="post" action="/settings/wifi/reset" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${field('Type reset to confirm', '<input name="confirm" autocomplete="off" required>')}
        <button type="submit">Reset Wi-Fi</button>
      </form>
      <h2>Password</h2>
      <p class="muted">Signed in as ${esc(username)}. Changing the password signs out every other session.</p>
      ${passwordError ? `<p class="flash bad">${esc(passwordError)}</p>` : ''}
      <form method="post" action="/settings/password" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        ${field('Current password', '<input name="current" type="password" autocomplete="current-password" required>')}
        ${field('New password', '<input name="password" type="password" autocomplete="new-password" required minlength="12">')}
        ${field('New password again', '<input name="password2" type="password" autocomplete="new-password" required minlength="12">')}
        ${field('Authentication code', '<input name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required>')}
        <button type="submit">Change password</button>
      </form>`,
  });
}

module.exports = {
  esc,
  layout,
  loginPage,
  recoverPage,
  setupPage,
  totpPage,
  livePage,
  tagsPage,
  logPage,
  settingsPage,
};
