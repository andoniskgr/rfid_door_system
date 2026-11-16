'use strict';

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function localParts(date, timeZone) {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  const parts = Object.fromEntries(fmt.formatToParts(date).map((part) => [part.type, part.value]));
  // Some engines report midnight as hour 24.
  if (parts.hour === '24') parts.hour = '00';
  return parts;
}

function currentOffsetMin(timeZone, date = new Date()) {
  const parts = localParts(date, timeZone);
  const asUtc = Date.UTC(
    Number(parts.year),
    Number(parts.month) - 1,
    Number(parts.day),
    Number(parts.hour),
    Number(parts.minute),
    Number(parts.second),
  );
  return Math.round((asUtc - date.getTime()) / 60000);
}

function localDay(date, timeZone) {
  const parts = localParts(date, timeZone);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function localHm(date, timeZone) {
  const parts = localParts(date, timeZone);
  return `${parts.hour}:${parts.minute}`;
}

function shouldRunDaily(lastDay, date, timeZone, afterHm) {
  if (localHm(date, timeZone) < afterHm) return false;
  return lastDay !== localDay(date, timeZone);
}

function formatTs(ts, timeZone) {
  if (!Number.isInteger(ts)) return '';
  const parts = localParts(new Date(ts * 1000), timeZone);
  const month = MONTHS[Number(parts.month) - 1] || parts.month;
  return `${parts.day} ${month} ${parts.year}, ${parts.hour}:${parts.minute}:${parts.second}`;
}

function formatIso(ts, timeZone) {
  const date = new Date(ts * 1000);
  const parts = localParts(date, timeZone);
  const offset = currentOffsetMin(timeZone, date);
  const sign = offset >= 0 ? '+' : '-';
  const abs = Math.abs(offset);
  const hh = String(Math.floor(abs / 60)).padStart(2, '0');
  const mm = String(abs % 60).padStart(2, '0');
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}:${parts.second}${sign}${hh}:${mm}`;
}

module.exports = {
  localParts,
  currentOffsetMin,
  localDay,
  localHm,
  shouldRunDaily,
  formatTs,
  formatIso,
};
