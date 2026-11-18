'use strict';

const { parseSchedule } = require('../../contract/policy');
const { currentOffsetMin, localParts } = require('./timeutil');

const DAY_NAMES = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

function normalizeHm(value) {
  const match = /^(\d{2}):(\d{2})(?::\d{2})?$/.exec(String(value || ''));
  if (!match) throw new Error('Enter times as HH:MM');
  const hour = Number(match[1]);
  const minute = Number(match[2]);
  if (hour > 23 || minute > 59) throw new Error('Enter times as HH:MM');
  return `${match[1]}:${match[2]}`;
}

function asDayList(value) {
  const raw = value == null || value === '' ? [] : (Array.isArray(value) ? value : [value]);
  return [...new Set(raw.map(Number))].filter((day) => day >= 1 && day <= 7).sort((a, b) => a - b);
}

// all_hours wins. An empty form means all hours. A partial form is an error.
function buildSchedule({ allHours, days, start, end }) {
  if (allHours) return null;
  const picked = asDayList(days);
  const hasTime = Boolean(start || end);
  if (!picked.length && !hasTime) return null;
  if (!picked.length || !start || !end) {
    throw new Error('Choose at least one day and both times, or choose all hours.');
  }
  const startHm = normalizeHm(start);
  const endHm = normalizeHm(end);
  const parts = [];
  let index = 0;
  while (index < picked.length) {
    let endIndex = index;
    while (endIndex + 1 < picked.length && picked[endIndex + 1] === picked[endIndex] + 1) endIndex += 1;
    parts.push(index === endIndex ? String(picked[index]) : `${picked[index]}-${picked[endIndex]}`);
    index = endIndex + 1;
  }
  const sch = `${parts.join(',')},${startHm}-${endHm}`;
  parseSchedule(sch);
  return sch;
}

function splitSchedule(sch) {
  if (!sch) return { allHours: true, days: [1, 2, 3, 4, 5, 6, 7], start: '08:00', end: '20:00' };
  const parsed = parseSchedule(sch);
  const days = parsed.days ? [...parsed.days].sort((a, b) => a - b) : [1, 2, 3, 4, 5, 6, 7];
  return {
    allHours: false,
    days,
    start: hm(parsed.start),
    end: hm(parsed.end),
  };
}

function hm(minutes) {
  const hour = Math.floor(minutes / 60);
  const minute = minutes % 60;
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function assertRealDate(year, month, day) {
  const check = new Date(Date.UTC(year, month - 1, day));
  if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) {
    throw new Error('Enter a real date');
  }
}

function zonedTimeToUtc(year, month, day, hour, minute, timeZone) {
  const utcGuess = Date.UTC(year, month - 1, day, hour, minute, 0);
  const offset = currentOffsetMin(timeZone, new Date(utcGuess));
  let utc = utcGuess - offset * 60000;
  const offset2 = currentOffsetMin(timeZone, new Date(utc));
  if (offset2 !== offset) utc = utcGuess - offset2 * 60000;
  return Math.floor(utc / 1000);
}

// The tag works through the chosen local date. exp is the next local midnight.
function expiryFromDate(dateStr, timeZone) {
  if (dateStr == null || dateStr === '') return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr);
  if (!match) throw new Error('Enter a date as YYYY-MM-DD');
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  assertRealDate(year, month, day);
  const next = new Date(Date.UTC(year, month - 1, day + 1));
  return zonedTimeToUtc(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate(), 0, 0, timeZone);
}

function startOfLocalDay(dateStr, timeZone) {
  if (dateStr == null || dateStr === '') return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  try {
    assertRealDate(year, month, day);
  } catch {
    return null;
  }
  return zonedTimeToUtc(year, month, day, 0, 0, timeZone);
}

function expiryToDateInput(exp, timeZone) {
  if (!Number.isInteger(exp)) return '';
  const parts = localParts(new Date((exp - 1) * 1000), timeZone);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function cleanName(name) {
  const text = String(name || '').replace(/[\u0000-\u001f]/g, '').trim();
  if (text.length > 80) throw new Error('Name must be 80 characters or less');
  return text || 'Unnamed';
}

module.exports = {
  DAY_NAMES,
  buildSchedule,
  splitSchedule,
  expiryFromDate,
  expiryToDateInput,
  startOfLocalDay,
  cleanName,
};
