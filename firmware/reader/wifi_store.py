# The network the reader should join. A saved file wins over secrets.py,
# including a cleared file after a reset from the settings page.

import json
import os

PATH = "/wifi.json"


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


def load(secrets_mod):
    saved = _load(PATH)
    if isinstance(saved, dict) and "ssid" in saved:
        ssid = saved.get("ssid")
        password = saved.get("password")
        if not isinstance(ssid, str):
            ssid = ""
        if not isinstance(password, str):
            password = ""
        return ssid, password
    ssid = getattr(secrets_mod, "WIFI_SSID", "") or ""
    password = getattr(secrets_mod, "WIFI_PASSWORD", "") or ""
    if not isinstance(ssid, str):
        ssid = ""
    if not isinstance(password, str):
        password = ""
    return ssid, password


def save(ssid, password):
    _save(PATH, {"ssid": ssid, "password": password})
