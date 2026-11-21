# Offline decisions for the Pico. These follow contract/policy.js.

from crypto_util import hmac_hex, random_id

ONLINE_WAIT_MS = 1200
UID_DEBOUNCE_MS = 2000
# The actuator still publishes every 30 seconds. The reader sleeps, so it
# checks in on MAINTAIN_S instead. The server allows that when status says sleeping.
HEARTBEAT_S = 30
IDLE_POLL_MS = 300
MAINTAIN_S = 600
LINK_RETRY_S = 30
KEEPALIVE_S = 60
OPEN_SKEW_S = 30
ALLOWLIST_MAX = 100
LOG_BATCH = 10
LOG_QUEUE = 50
OPEN_MIN_MS = 200
OPEN_MAX_MS = 10000
OPEN_DEFAULT_MS = 3000


def normalize_uid(uid):
    if not isinstance(uid, str):
        raise ValueError("uid must be a string")
    cleaned = []
    for char in uid:
        if char in ": \t":
            continue
        cleaned.append(char.upper())
    text = "".join(cleaned)
    length = len(text)
    if length not in (8, 14, 20):
        raise ValueError("uid must be 4, 7, or 10 bytes of hex")
    for char in text:
        if char not in "0123456789ABCDEF":
            raise ValueError("uid must be 4, 7, or 10 bytes of hex")
    return text


def allowlist_hash(key_hex, uid):
    return hmac_hex(key_hex, normalize_uid(uid))


def _clock(hour_text, minute_text):
    hour = int(hour_text)
    minute = int(minute_text)
    if hour > 23 or minute > 59:
        raise ValueError("bad schedule time")
    return hour * 60 + minute


def parse_schedule(sch):
    if sch is None or sch == "":
        return None
    if not isinstance(sch, str):
        raise ValueError("sch must be a string")
    comma = sch.find(",")
    if comma < 1:
        raise ValueError("bad schedule")
    days_text = sch[:comma]
    clock = sch[comma + 1:]
    if len(clock) != 11 or clock[2] != ":" or clock[5] != "-" or clock[8] != ":":
        raise ValueError("bad schedule")
    start = _clock(clock[0:2], clock[3:5])
    end = _clock(clock[6:8], clock[9:11])
    if days_text == "*":
        return (None, start, end)
    days = set()
    for token in days_text.split(","):
        if len(token) == 1 and token in "1234567":
            days.add(int(token))
            continue
        if (
            len(token) == 3
            and token[1] == "-"
            and token[0] in "1234567"
            and token[2] in "1234567"
        ):
            first = int(token[0])
            last = int(token[2])
            if last < first:
                raise ValueError("bad schedule range")
            for day in range(first, last + 1):
                days.add(day)
            continue
        raise ValueError("bad schedule days")
    return (days, start, end)


def civil_from_unix(ts, offset_min):
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise ValueError("ts must be an integer")
    if not isinstance(offset_min, int) or isinstance(offset_min, bool):
        raise ValueError("utc_offset_min must be an integer")
    local = ts + offset_min * 60
    days = local // 86400
    seconds = local % 86400
    return (((days + 3) % 7) + 1, seconds // 60)


def _in_window(minutes, start, end):
    if start == end:
        return False
    if end < start:
        return minutes >= start or minutes < end
    return minutes >= start and minutes < end


def schedule_allows(ts, offset_min, sch):
    window = parse_schedule(sch)
    if window is None:
        return True
    days, start, end = window
    weekday, minutes = civil_from_unix(ts, offset_min)
    if days is not None and weekday not in days:
        return False
    return _in_window(minutes, start, end)


def decide_offline(key_hex, uid, entries, ts, utc_offset_min):
    try:
        digest = allowlist_hash(key_hex, uid)
    except ValueError:
        return {"granted": False, "reason": "unknown"}
    if not isinstance(ts, int) or isinstance(ts, bool):
        return {"granted": False, "reason": "time_unsynced"}
    found = None
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get("h") == digest:
            found = entry
            break
    if found is None:
        return {"granted": False, "reason": "unknown"}
    exp = found.get("exp")
    if isinstance(exp, int) and not isinstance(exp, bool) and ts >= exp:
        return {"granted": False, "reason": "expired"}
    try:
        if not schedule_allows(ts, utc_offset_min, found.get("sch")):
            return {"granted": False, "reason": "outside_hours"}
    except ValueError:
        return {"granted": False, "reason": "outside_hours"}
    return {"granted": True, "reason": "offline_ok"}


def open_canonical(cmd):
    return "v1|{}|{}|{}|{}|{}|{}".format(
        cmd["id"], cmd["ts"], cmd["nonce"], cmd["duration_ms"], cmd["source"], cmd["reason"]
    )


def sign_open(secret_hex, ts, duration_ms, reason):
    if duration_ms < OPEN_MIN_MS or duration_ms > OPEN_MAX_MS:
        raise ValueError("duration out of range")
    cmd = {
        "schema": 1,
        "id": random_id(),
        "ts": ts,
        "nonce": random_id(),
        "duration_ms": duration_ms,
        "source": "reader",
        "reason": reason,
    }
    cmd["mac"] = hmac_hex(secret_hex, open_canonical(cmd))
    return cmd
