'use strict';

const session = require('express-session');

class SqliteSessionStore extends session.Store {
  constructor(db) {
    super();
    this.db = db;
  }

  get(sid, callback) {
    try {
      const row = this.db.prepare('SELECT data, expires FROM sessions WHERE sid = ?').get(sid);
      if (!row || row.expires < Date.now()) return callback(null, null);
      const data = JSON.parse(row.data);
      if (data.cookie && typeof data.cookie.expires === 'string') {
        data.cookie.expires = new Date(data.cookie.expires);
      }
      return callback(null, data);
    } catch (err) {
      return callback(err);
    }
  }

  set(sid, sess, callback) {
    try {
      const expires = expiryMs(sess);
      this.db.prepare(`
        INSERT INTO sessions (sid, data, expires) VALUES (?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires = excluded.expires
      `).run(sid, JSON.stringify(sess), expires);
      return callback(null);
    } catch (err) {
      return callback(err);
    }
  }

  destroy(sid, callback) {
    try {
      this.db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
      return callback(null);
    } catch (err) {
      return callback(err);
    }
  }

  touch(sid, sess, callback) {
    this.set(sid, sess, callback);
  }
}

function expiryMs(sess) {
  const exp = sess.cookie && sess.cookie.expires;
  if (exp) {
    const time = new Date(exp).getTime();
    if (!Number.isNaN(time)) return time;
  }
  return Date.now() + 12 * 60 * 60 * 1000;
}

module.exports = { SqliteSessionStore };
