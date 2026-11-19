# Host check for the Pico decision code. Run from this directory:
#   python3 check_policy.py

import calendar
import datetime
import json
import os
import sys

from crypto_util import hmac_hex
from policy import (
    allowlist_hash,
    civil_from_unix,
    decide_offline,
    open_canonical,
    schedule_allows,
    sign_open,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VECTORS = json.load(open(os.path.join(ROOT, "contract", "examples", "vectors.json")))
ALLOW = json.load(open(os.path.join(ROOT, "contract", "examples", "allowlist.json")))

failed = 0


def check(cond, message):
    global failed
    if cond:
        print("ok  " + message)
        return
    failed += 1
    print("FAIL  " + message)


def at(iso):
    parsed = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
    return calendar.timegm(parsed.timetuple())


def main():
    opened = VECTORS["open"]
    check(open_canonical(opened) == VECTORS["canonical"], "open canonical string")
    check(
        hmac_hex(VECTORS["open_secret_hex"], VECTORS["canonical"]) == opened["mac"],
        "open MAC matches vectors.json",
    )
    check(allowlist_hash(VECTORS["allowlist_key_hex"], VECTORS["uid"]) == VECTORS["uid_hash"], "allowlist hash")
    check(
        allowlist_hash(VECTORS["allowlist_key_hex"], "a1:b2:c3:d4") == VECTORS["uid_hash"],
        "hash uses normalized UID",
    )
    check(civil_from_unix(0, 0) == (4, 0), "1970-01-01 is Thursday")
    check(civil_from_unix(-1, 0)[0] == 3, "the second before 1970 is Wednesday")

    friday = at("2026-11-13T15:04:00Z")
    weekdays = "1-5,08:00-20:00"
    check(schedule_allows(friday, 0, weekdays), "Friday 15:04 is inside 08:00-20:00")
    check(not schedule_allows(at("2026-11-13T21:00:00Z"), 0, weekdays), "Friday 21:00 is outside")
    check(not schedule_allows(at("2026-11-14T12:00:00Z"), 0, weekdays), "Saturday is outside Mon-Fri")
    check(schedule_allows(at("2026-11-13T08:00:00Z"), 0, weekdays), "08:00 is inside")
    check(not schedule_allows(at("2026-11-13T20:00:00Z"), 0, weekdays), "20:00 is outside")
    check(schedule_allows(at("2026-11-13T06:30:00Z"), 120, weekdays), "UTC 06:30 with +120 is local 08:30")
    check(schedule_allows(at("2026-11-14T23:00:00Z"), 0, "*,22:00-06:00"), "23:00 is inside overnight")
    check(not schedule_allows(at("2026-11-15T06:00:00Z"), 0, "*,22:00-06:00"), "06:00 is outside overnight")
    check(not schedule_allows(friday, 0, "1-5,08:00-08:00"), "zero-length window matches nothing")
    check(schedule_allows(friday, 0, None), "omitted schedule is all hours")

    try:
        from policy import parse_schedule
        parse_schedule("5-1,08:00-20:00")
        check(False, "descending day range is rejected")
    except ValueError:
        check(True, "descending day range is rejected")

    hit = decide_offline(
        VECTORS["allowlist_key_hex"],
        "A1B2C3D4",
        ALLOW["entries"],
        friday,
        0,
    )
    check(hit["granted"] and hit["reason"] == "offline_ok", "known tag during hours is offline_ok")
    missed = decide_offline(VECTORS["allowlist_key_hex"], "DEADBEEF", ALLOW["entries"], friday, 0)
    check(not missed["granted"] and missed["reason"] == "unknown", "absent tag is unknown")
    unsynced = decide_offline(VECTORS["allowlist_key_hex"], VECTORS["uid"], ALLOW["entries"], None, 0)
    check(unsynced["reason"] == "time_unsynced", "offline with no clock is time_unsynced")
    expired = decide_offline(
        VECTORS["allowlist_key_hex"],
        VECTORS["uid"],
        ALLOW["entries"],
        ALLOW["entries"][0]["exp"],
        0,
    )
    check(expired["reason"] == "expired", "ts equal to exp is expired")

    signed = sign_open(VECTORS["open_secret_hex"], opened["ts"], 3000, "offline")
    check(hmac_hex(VECTORS["open_secret_hex"], open_canonical(signed)) == signed["mac"], "signed open verifies")
    check(signed["source"] == "reader" and signed["reason"] == "offline", "reader open source and reason")

    if failed:
        print("{} failed".format(failed))
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
