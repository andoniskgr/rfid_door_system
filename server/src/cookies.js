'use strict';

const crypto = require('crypto');
const dbApi = require('./db');

// Same construction as the cookie-signature package used by express-session.
function unsign(value, secret) {
  const dot = value.lastIndexOf('.');
  if (dot < 1) return false;
  const text = value.slice(0, dot);
  const mac = crypto.createHmac('sha256', secret).update(text).digest('base64').replace(/=+$/, '');
  const expected = Buffer.from(`${text}.${mac}`);
  const actual = Buffer.from(value);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return false;
  return text;
}

function readCookie(header, name) {
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

function sessionFromRequest(db, config, req) {
  const raw = readCookie(req.headers.cookie, 'door_sid');
  if (!raw || !raw.startsWith('s:')) return null;
  const sid = unsign(raw.slice(2), config.sessionSecret);
  if (!sid) return null;
  const data = dbApi.readSession(db, sid);
  if (!data || !data.admin || !data.totpOk) return null;
  return data;
}

module.exports = { unsign, readCookie, sessionFromRequest };
