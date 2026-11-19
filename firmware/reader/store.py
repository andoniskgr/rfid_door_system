# Allowlist and the offline log, stored on the Pico flash.

import json
import os

from policy import ALLOWLIST_MAX, LOG_QUEUE


def _pulse(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 200 or value > 10000:
        return None
    return value


def _load(path):
    try:
        with open(path, "r") as handle:
            return json.loads(handle.read())
    except (OSError, ValueError):
        return None


def _save(path, obj):
    temp = path + ".tmp"
    with open(temp, "w") as handle:
        handle.write(json.dumps(obj))
    try:
        os.remove(path)
    except OSError:
        pass
    os.rename(temp, path)


class Store:
    def __init__(self, allow_path="/allowlist.json", log_path="/log.json"):
        self.allow_path = allow_path
        self.log_path = log_path
        saved = _load(allow_path) or {}
        self.version = saved.get("version") if isinstance(saved.get("version"), int) else 0
        offset = saved.get("utc_offset_min")
        self.utc_offset_min = offset if isinstance(offset, int) and not isinstance(offset, bool) else 0
        entries = saved.get("entries")
        self.entries = entries if isinstance(entries, list) else []
        self.open_ms = _pulse(saved.get("open_ms"))
        logged = _load(log_path) or {}
        rows = logged.get("entries")
        self.entries_log = rows if isinstance(rows, list) else []

    def accept_allowlist(self, message):
        if not isinstance(message, dict):
            return False
        if message.get("schema") != 1 or message.get("hash") != "hmac-sha256":
            return False
        version = message.get("version")
        offset = message.get("utc_offset_min")
        entries = message.get("entries")
        if isinstance(version, bool) or not isinstance(version, int):
            return False
        if isinstance(offset, bool) or not isinstance(offset, int):
            return False
        if not isinstance(entries, list) or len(entries) > ALLOWLIST_MAX:
            return False
        if version < self.version:
            return False
        pulse = _pulse(message.get("open_ms"))
        if pulse is None:
            pulse = self.open_ms
        self.version = version
        self.utc_offset_min = offset
        self.entries = entries
        self.open_ms = pulse
        saved = {
            "version": version,
            "utc_offset_min": offset,
            "entries": entries,
        }
        if pulse is not None:
            saved["open_ms"] = pulse
        _save(self.allow_path, saved)
        return True

    def enqueue(self, entry):
        self.entries_log.append(entry)
        if len(self.entries_log) > LOG_QUEUE:
            self.entries_log = self.entries_log[-LOG_QUEUE:]
        self._save_log()

    def mark_not_actuated(self, read_id):
        for entry in self.entries_log:
            if entry.get("id") == read_id:
                entry["granted"] = False
                entry["reason"] = "not_actuated"
                entry["open_id"] = None
        self._save_log()

    def take_batch(self, limit):
        return self.entries_log[:limit]

    def drop_ids(self, ids):
        keep = []
        for entry in self.entries_log:
            if entry.get("id") not in ids:
                keep.append(entry)
        self.entries_log = keep
        self._save_log()

    def _save_log(self):
        _save(self.log_path, {"entries": self.entries_log})
