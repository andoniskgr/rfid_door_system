# Pico W entrance reader. A tap publishes the UID. The door stays closed
# until the ESP-01 actuator is listening for door/actuator/open.
#
# Between taps the radio is off and the RC522 is held in reset. The Pico
# polls for a card every few hundred milliseconds, then sleeps again.
# Wi-Fi comes up only for a tap or a periodic check-in.

import json
import time

import network
import ntptime
from machine import PWM, Pin, SoftSPI

import pins
import secrets
import setup_ap
import wifi_store
from crypto_util import random_id
from mfrc522 import MFRC522
from mqtt_client import MqttClient
from policy import (
    IDLE_POLL_MS,
    LINK_RETRY_S,
    LOG_BATCH,
    MAINTAIN_S,
    ONLINE_WAIT_MS,
    OPEN_SKEW_S,
    UID_DEBOUNCE_MS,
    decide_offline,
    sign_open,
)
from store import Store
from ui import Ui

FW = "0.6.1"
CLIENT_ID = "door-reader"


def _int(value, default):
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def _printable(value):
    for ch in value:
        code = ord(ch)
        if code < 32 or code == 127:
            return False
    return True


def _setup_secret(value):
    return (
        isinstance(value, str)
        and len(value) >= 8
        and setup_ap.credentials_ok("setup", value)
        and _printable(value)
    )


def open_ms(store):
    value = _int(store.open_ms, 0)
    if value < 200 or value > 10000:
        value = _int(getattr(secrets, "OPEN_MS", 3000), 3000)
    if value < 200 or value > 10000:
        return 3000
    return value


class Clock:
    def __init__(self):
        self.synced = False

    def sync(self):
        try:
            ntptime.timeout = 5
            ntptime.settime()
        except Exception as err:
            print("ntp", err)
            return False
        if time.gmtime()[0] < 2024:
            return False
        self.synced = True
        return True

    def unix(self):
        if not self.synced:
            return None
        ts = time.time()
        if ts > 1600000000:
            return ts
        if ts > 700000000:
            return ts + 946684800
        return None


class Reader:
    def __init__(self):
        self.wlan = None
        self.clock = Clock()
        self.store = Store()
        self.mqtt = MqttClient(
            secrets.MQTT_HOST,
            _int(getattr(secrets, "MQTT_PORT", 1883), 1883),
            secrets.MQTT_USER,
            secrets.MQTT_PASS,
            CLIENT_ID,
        )
        self.mqtt.on_message = self.on_message
        self.ui = Ui(
            Pin(pins.LED_GREEN, Pin.OUT),
            Pin(pins.LED_RED, Pin.OUT),
            PWM(Pin(pins.BUZZER)),
        )
        self.spi = self._open_spi()
        self.irq = Pin(pins.IRQ, Pin.IN, Pin.PULL_DOWN)
        self.rfid = MFRC522(
            self.spi,
            Pin(pins.SDA, Pin.OUT, value=1),
            Pin(pins.RST, Pin.OUT, value=1),
        )
        self.rfid.power_down()
        self.boot = time.ticks_ms()
        self.ssid, self.password = wifi_store.load(secrets)
        self.wifi_cmd = None
        self.scan_report = None
        self.setup_pin = Pin(pins.SETUP, Pin.IN, Pin.PULL_UP)
        self.setup_hold = 0
        self.setup_armed = True
        self.wifi_try = 0
        self.ntp_try = 0
        self.mqtt_try = 0
        self.status_at = 0
        self.upload_at = 0
        self.hold_try = 0
        self.last_uid = None
        self.last_uid_at = 0
        self.holding = None
        self.feedback = {}
        self.radio = False
        self.ui_on = True
        self.link_at = time.ticks_ms()
        self.link_gap = 0

    def run(self):
        print("door reader", FW)
        if not self.ssid:
            print("no wifi saved")
            try:
                self._enter_setup(self._setup_ap_password())
            except Exception as err:
                print("setup", err)
        while True:
            try:
                self._idle_once()
            except Exception as err:
                print("loop", err)
                time.sleep_ms(200)

    def _idle_once(self):
        self._check_setup_button()
        if self._link_due():
            self._session(None)
            return
        uid = self._probe()
        if uid and self._accept_uid(uid):
            print("tap", uid)
            self._ui_wake()
            self.ui.tick()
            self._session(uid)
            return
        self._nap(IDLE_POLL_MS)

    def _link_due(self):
        return time.ticks_diff(time.ticks_ms(), self.link_at) >= self.link_gap

    def _session(self, uid):
        # One radio window: a tap, or the periodic allowlist check.
        self._ui_wake()
        connected = False
        try:
            if self.ssid:
                self._radio_on()
                self.wifi_try = 0
                self.ntp_try = 0
                self.mqtt_try = 0
                self._ensure_wifi()
                connected = self._wlan().isconnected()
                if connected:
                    self._ensure_ntp()
                    self._ensure_mqtt()
                    if self.mqtt.connected:
                        try:
                            self.mqtt.poll(400)
                        except OSError as err:
                            print("mqtt", err)
                            self.mqtt.close()
                    self._take_wifi_cmd()
            if uid:
                try:
                    self._on_tap(uid)
                except Exception as err:
                    print("tap failed", err)
            while self.holding is not None:
                self._service_hold()
                if self.holding is None:
                    break
                if self.ssid and not self.mqtt.connected:
                    self._ensure_wifi()
                    self._ensure_mqtt()
                    connected = self.wlan is not None and self.wlan.isconnected()
                if self.mqtt.connected:
                    try:
                        self.mqtt.poll(50)
                    except OSError as err:
                        print("mqtt", err)
                        self.mqtt.close()
                time.sleep_ms(50)
            if self.mqtt.connected:
                self._flush_logs()
                self._publish_status()
                self.status_at = time.ticks_ms()
                connected = True
        finally:
            if connected:
                self.link_at = time.ticks_ms()
                self.link_gap = MAINTAIN_S * 1000
            elif self.ssid:
                self.link_at = time.ticks_ms()
                self.link_gap = LINK_RETRY_S * 1000
            else:
                self.link_at = time.ticks_ms()
                self.link_gap = MAINTAIN_S * 1000
            self._radio_off()

    def _probe(self):
        try:
            self._bus()
            self.rfid.power_up()
            return self.rfid.read_uid()
        except Exception as err:
            print("rfid", err)
            return None
        finally:
            try:
                self.rfid.power_down()
            except Exception:
                pass

    def _open_spi(self):
        return SoftSPI(
            baudrate=1000000,
            polarity=0,
            phase=0,
            sck=Pin(pins.SCK),
            mosi=Pin(pins.MOSI),
            miso=Pin(pins.MISO),
        )

    def _bus(self):
        try:
            self.spi.init(baudrate=1000000, polarity=0, phase=0)
        except Exception:
            self.spi = self._open_spi()
            self.rfid.spi = self.spi

    def _nap(self, ms):
        self._radio_off()
        try:
            self.rfid.power_down()
        except Exception:
            pass
        self._ui_sleep()
        time.sleep_ms(ms)

    def _wlan(self):
        if self.wlan is None:
            self.wlan = network.WLAN(network.STA_IF)
        return self.wlan

    def _radio_on(self):
        self.radio = True
        try:
            self._wlan().active(True)
        except OSError as err:
            print("wifi", err)

    def _radio_off(self):
        self.mqtt.close()
        wlan = self.wlan
        self.wlan = None
        if wlan is not None or self.radio:
            if wlan is None:
                try:
                    wlan = network.WLAN(network.STA_IF)
                except OSError:
                    wlan = None
            if wlan is not None:
                try:
                    wlan.disconnect()
                except OSError:
                    pass
                try:
                    wlan.active(False)
                except OSError:
                    pass
                deinit = getattr(wlan, "deinit", None)
                if callable(deinit):
                    try:
                        deinit()
                    except Exception as err:
                        print("wifi off", err)
            try:
                network.WLAN(network.AP_IF).active(False)
            except OSError:
                pass
        self.radio = False

    def _ui_wake(self):
        if self.ui_on:
            return
        self.ui.buzzer = PWM(Pin(pins.BUZZER))
        self.ui_on = True

    def _ui_sleep(self):
        self.ui.off()
        try:
            self.ui.buzzer.deinit()
        except Exception:
            pass
        self.ui_on = False

    def _flush_logs(self):
        for _ in range(5):
            queued = len(self.store.entries_log)
            if not queued or not self.mqtt.connected:
                return
            self.upload_at = 0
            self._upload()
            if len(self.store.entries_log) == queued:
                return

    def _due(self, stamp, gap_ms):
        return time.ticks_diff(time.ticks_ms(), stamp) >= gap_ms

    def _setup_ap_password(self):
        value = getattr(secrets, "SETUP_AP_PASSWORD", "") or ""
        if _setup_secret(value):
            return value
        return ""

    def _join(self, timeout_ms):
        if not self.ssid:
            return False
        self._radio_on()
        wlan = self._wlan()
        self.mqtt.close()
        try:
            wlan.disconnect()
        except OSError:
            pass
        try:
            wlan.active(False)
        except OSError:
            pass
        time.sleep_ms(100)
        wlan.active(True)
        time.sleep_ms(100)
        try:
            wlan.connect(self.ssid, self.password)
        except OSError as err:
            print("wifi", err)
            return False
        deadline = time.ticks_add(time.ticks_ms(), timeout_ms)
        while time.ticks_diff(deadline, time.ticks_ms()) > 0:
            if wlan.isconnected():
                return True
            try:
                status = wlan.status()
            except OSError:
                status = 1
            if status in (-3, -2):
                return False
            time.sleep_ms(200)
        return wlan.isconnected()

    def _ensure_wifi(self):
        wlan = self._wlan()
        wlan.active(True)
        if wlan.isconnected():
            return
        self.mqtt.close()
        if not self.ssid or not self._due(self.wifi_try, 3000):
            return
        self.wifi_try = time.ticks_ms()
        if self._join(8000):
            print("wifi", wlan.ifconfig()[0])

    def _set_wifi(self, ssid, password):
        previous = (self.ssid, self.password)
        self.ssid = ssid
        self.password = password
        if self._join(20000):
            wifi_store.save(ssid, password)
            print("wifi", self._wlan().ifconfig()[0])
            return
        print("wifi rejected")
        self.ssid, self.password = previous
        if previous[0] and self._join(15000):
            print("wifi", self._wlan().ifconfig()[0])

    def _enter_setup(self, setup_password):
        previous = (self.ssid, self.password)
        self.radio = True
        self._ui_wake()
        self.mqtt.close()
        try:
            self._wlan().disconnect()
        except OSError:
            pass
        started = time.ticks_ms()
        notice = ""
        joined = False
        while time.ticks_diff(time.ticks_ms(), started) < 600000:
            left = 600 - time.ticks_diff(time.ticks_ms(), started) // 1000
            if left < 20:
                break
            chosen = setup_ap.serve(self.ui, left, setup_password, notice)
            if not chosen:
                break
            self.ssid, self.password = chosen
            if self._join(15000):
                wifi_store.save(self.ssid, self.password)
                print("wifi", self._wlan().ifconfig()[0])
                joined = True
                break
            print("wifi rejected")
            notice = "That network did not connect. Check the name and password."
        self.ui.off()
        if joined:
            return
        self.ssid, self.password = previous
        if previous[0] and self._join(15000):
            print("wifi", self._wlan().ifconfig()[0])
            return
        if not previous[0]:
            wifi_store.save("", "")

    def _publish_scan(self, scan_id):
        networks = setup_ap.nearby_networks(self._wlan())
        self.scan_report = {"id": scan_id, "networks": networks}
        print("scan", len(networks))
        self._publish_status()

    def _take_wifi_cmd(self):
        cmd = self.wifi_cmd
        if cmd is None:
            return
        self.wifi_cmd = None
        if not isinstance(cmd, dict) or cmd.get("schema") != 1:
            return
        action = cmd.get("action")
        if action == "scan":
            scan_id = cmd.get("id")
            if isinstance(scan_id, str) and len(scan_id) == 32:
                self._publish_scan(scan_id)
            return
        if action == "set":
            ssid = cmd.get("ssid")
            password = cmd.get("password")
            if not isinstance(password, str):
                password = ""
            if setup_ap.credentials_ok(ssid, password):
                self._set_wifi(ssid, password)
            return
        if action == "forget" and _setup_secret(cmd.get("setup_password")):
            wifi_store.save("", "")
            self.ssid = ""
            self.password = ""
            self._enter_setup(cmd.get("setup_password"))

    def _check_setup_button(self):
        held = self.setup_pin.value() == 0
        if not held:
            self.setup_hold = 0
            self.setup_armed = True
            return
        if not self.setup_armed:
            return
        now = time.ticks_ms()
        if self.setup_hold == 0:
            self.setup_hold = now
            return
        if time.ticks_diff(now, self.setup_hold) < 3000:
            return
        self.setup_armed = False
        self.setup_hold = 0
        print("wifi setup button")
        self._enter_setup(self._setup_ap_password())

    def _ensure_ntp(self):
        if self.clock.synced or self.wlan is None or not self.wlan.isconnected():
            return
        if not self._due(self.ntp_try, 15000):
            return
        self.ntp_try = time.ticks_ms()
        if self.clock.sync():
            print("ntp", self.clock.unix())

    def _ensure_mqtt(self):
        if self.mqtt.connected or self.wlan is None or not self.wlan.isconnected():
            return
        if not self._due(self.mqtt_try, 3000):
            return
        self.mqtt_try = time.ticks_ms()
        try:
            self.mqtt.connect()
            self.mqtt.subscribe([
                "door/reader/allowlist",
                "door/reader/feedback",
                "door/reader/wifi",
            ])
            print("mqtt connected")
            self._publish_status()
            self.status_at = time.ticks_ms()
        except OSError as err:
            print("mqtt", err)
            self.mqtt.close()

    def on_message(self, topic, data):
        try:
            message = json.loads(data)
        except (ValueError, TypeError):
            return None
        if topic == "door/reader/allowlist":
            if self.store.accept_allowlist(message):
                print("allowlist", self.store.version, len(self.store.entries))
            return None
        if topic == "door/reader/wifi" and isinstance(message, dict):
            self.wifi_cmd = message
            return None
        if topic == "door/reader/feedback" and isinstance(message, dict):
            read_id = message.get("id")
            if isinstance(read_id, str):
                while len(self.feedback) > 4:
                    self.feedback.pop(list(self.feedback.keys())[0])
                self.feedback[read_id] = message
            return read_id
        return None

    def _accept_uid(self, uid):
        now = time.ticks_ms()
        if uid == self.last_uid and time.ticks_diff(now, self.last_uid_at) < UID_DEBOUNCE_MS:
            return False
        self.last_uid = uid
        self.last_uid_at = now
        return True

    def _on_tap(self, uid):
        read_id = random_id()
        ts = self.clock.unix()
        if self.mqtt.connected:
            body = json.dumps({
                "schema": 1,
                "id": read_id,
                "ts": ts if ts is not None else 0,
                "device": secrets.DEVICE,
                "uid": uid,
            })
            if self.mqtt.publish("door/reader/uid", body, False):
                if read_id not in self.feedback:
                    self.mqtt.wait_topic("door/reader/feedback", read_id, ONLINE_WAIT_MS)
                feedback = self.feedback.pop(read_id, None)
                if feedback is not None:
                    granted = feedback.get("granted") is True
                    print("feedback", uid, feedback.get("reason"))
                    self.ui.show(granted)
                    return
        self._decide_locally(read_id, uid, ts)

    def _decide_locally(self, read_id, uid, ts):
        if ts is None:
            decision = {"granted": False, "reason": "time_unsynced"}
        else:
            decision = decide_offline(
                secrets.ALLOWLIST_HMAC_KEY,
                uid,
                self.store.entries,
                ts,
                self.store.utc_offset_min,
            )
        if not decision["granted"]:
            self._record(read_id, uid, ts, decision, None)
            self.ui.show(False)
            return
        cmd = sign_open(secrets.DOOR_HMAC_SECRET, ts, open_ms(self.store), "offline")
        if self.mqtt.connected and self._publish_open(cmd):
            self._record(read_id, uid, ts, decision, cmd["id"])
            self.ui.show(True)
            return
        self.holding = {
            "read_id": read_id,
            "uid": uid,
            "ts": ts,
            "cmd": cmd,
            "deadline": time.ticks_add(time.ticks_ms(), OPEN_SKEW_S * 1000),
        }
        self.hold_try = time.ticks_ms()
        print("holding open", uid)
        self.ui.show(False)

    def _service_hold(self):
        hold = self.holding
        if hold is None:
            return
        if time.ticks_diff(time.ticks_ms(), hold["deadline"]) >= 0:
            self.holding = None
            self._record(
                hold["read_id"],
                hold["uid"],
                hold["ts"],
                {"granted": False, "reason": "not_actuated"},
                None,
            )
            print("open dropped", hold["uid"])
            return
        if self.mqtt.connected and self._due(self.hold_try, 500):
            self.hold_try = time.ticks_ms()
            if self._publish_open(hold["cmd"]):
                self.holding = None
                self._record(
                    hold["read_id"],
                    hold["uid"],
                    hold["ts"],
                    {"granted": True, "reason": "offline_ok"},
                    hold["cmd"]["id"],
                )
                self.ui.show(True)
                return

    def _publish_open(self, cmd):
        return self.mqtt.publish("door/actuator/open", json.dumps(cmd), False)

    def _record(self, read_id, uid, ts, decision, open_id):
        entry = {
            "schema": 1,
            "id": read_id,
            "ts": ts if ts is not None else 0,
            "uid": uid,
            "device": secrets.DEVICE,
            "granted": True if decision["granted"] else False,
            "reason": decision["reason"],
            "allowlist_version": self.store.version,
            "open_id": open_id,
        }
        print(decision["reason"], uid)
        if self.mqtt.connected and self.mqtt.publish("door/reader/local", json.dumps(entry), False):
            return
        self.store.enqueue(entry)

    def _upload(self):
        if not self.mqtt.connected or not self._due(self.upload_at, 1000):
            return
        batch = self.store.take_batch(LOG_BATCH)
        if not batch:
            return
        self.upload_at = time.ticks_ms()
        now = self.clock.unix()
        body = json.dumps({
            "schema": 1,
            "id": random_id(),
            "ts": now if now is not None else 0,
            "entries": batch,
        })
        if self.mqtt.publish("door/reader/log", body, False):
            self.store.drop_ids([entry.get("id") for entry in batch])
            print("uploaded", len(batch))

    def _publish_status(self):
        if not self.mqtt.connected:
            return
        ip = "0.0.0.0"
        rssi = 0
        if self.wlan is not None and self.wlan.isconnected():
            try:
                ip = self.wlan.ifconfig()[0]
            except OSError:
                pass
            try:
                rssi = self.wlan.status("rssi")
            except (OSError, ValueError):
                rssi = 0
        if isinstance(rssi, bool) or not isinstance(rssi, int):
            rssi = 0
        now = self.clock.unix()
        body = {
            "schema": 1,
            "id": random_id(),
            "online": True,
            "ts": now if now is not None else 0,
            "fw": FW,
            "uptime_s": time.ticks_diff(time.ticks_ms(), self.boot) // 1000,
            "ip": ip,
            "ssid": self.ssid if isinstance(self.ssid, str) else "",
            "rssi": rssi,
            "ntp": self.clock.synced,
            "allowlist_version": self.store.version,
            "log_queued": len(self.store.entries_log),
            "sleeping": True,
        }
        report = self.scan_report
        if isinstance(report, dict):
            body["scan_id"] = report.get("id")
            body["networks"] = report.get("networks")
        if self.mqtt.publish("door/reader/status", json.dumps(body), True):
            self.scan_report = None


Reader().run()
