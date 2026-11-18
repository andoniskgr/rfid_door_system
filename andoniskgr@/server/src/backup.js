'use strict';

const fs = require('fs');
const path = require('path');

async function backupDatabase(db, backupDir) {
  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = path.join(backupDir, `door-${stamp}.sqlite`);
  await db.backup(dest);
  pruneBackups(backupDir, 14);
  return dest;
}

function pruneBackups(backupDir, keep = 14) {
  if (!fs.existsSync(backupDir)) return [];
  const files = fs.readdirSync(backupDir)
    .filter((name) => name.startsWith('door-') && name.endsWith('.sqlite'))
    .sort();
  const removed = [];
  while (files.length > keep) {
    const name = files.shift();
    fs.unlinkSync(path.join(backupDir, name));
    removed.push(name);
  }
  return removed;
}

module.exports = { backupDatabase, pruneBackups };
