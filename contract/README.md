# MQTT contract

This is the wire contract for the reader (Pico W), the actuator (ESP-01), and the server. `contract/policy.js` is the reference for schedules, allow/deny, and open-command checks. `node tools/self-test.js` locks it to `contract/examples/vectors.json`. The Pico port (MicroPython) and the server must follow those results. The ESP-01 must follow `classifyOpen`.

Payloads are JSON objects. `schema` is `1`. `ts` is Unix seconds. `id` and `nonce` are 32 lowercase hex characters (16 random bytes). Unknown fields are ignored. A missing required field is rejected.

Clients use a clean session, MQTT keepalive **60 seconds**, and QoS 1. The tools use their own client ids (`door-reader-sim`, `door-server-sim`) so a test does not disconnect a real device.

## Constants

| Name | Value | Meaning |
|---|---|---|
| Online wait | 1200 ms | Pico waits this long for feedback, then decides locally |
| UID debounce | 2000 ms | Same UID is ignored for this long |
| Heartbeat | 30 s | Retained status publish |
| MQTT keepalive | 60 s | Broker publishes the Last Will about 90 s after a hard drop |
| Offline threshold | 90 s | Server treats a silent device as offline |
| Open pulse | 3000 ms | Starting value. Settings can set 200–10000. The ESP-01 will not go past 10000 |
| Hard maximum | 10000 ms | Compiled into the ESP-01. A command cannot raise it |
| Clock window | ±30 s | Open command `ts` against the actuator clock |
| Nonce ring | 32 | Last accepted nonces, stored in flash |
| Allowlist cap | 100 entries | Larger retained messages are refused by the Pico |
| Log batch | 10 | Maximum entries in one `door/reader/log` message |
| Log queue | 50 | Oldest flash log is dropped after this |

## Topics

| Topic | Who publishes | Who subscribes | Retained |
|---|---|---|---|
| `door/reader/uid` | reader | server | no |
| `door/reader/feedback` | server | reader | no |
| `door/reader/local` | reader | server | no |
| `door/reader/log` | reader | server | no |
| `door/reader/allowlist` | server | reader | yes |
| `door/reader/wifi` | server | reader | **no** |
| `door/reader/status` | reader | server | yes |
| `door/actuator/open` | server, reader | actuator | **no** |
| `door/actuator/result` | actuator | server | no |
| `door/actuator/status` | actuator | server | yes |

`door/actuator/open` stays unretained. The actuator also rejects a command outside the 30-second window, so a command left on the broker cannot open the door later.

## Messages

Examples live in `contract/examples/`. The shapes below are the required fields.

**Tag read** `door/reader/uid`

```json
{ "schema": 1, "id": "<32 hex>", "ts": 1794582240, "device": "entrance", "uid": "A1B2C3D4" }
```

`uid` is uppercase hex, 4, 7, or 10 bytes, with no separators. `device` names the door.

**Feedback** `door/reader/feedback`. `id` is the read id. The Pico uses this for the LED and the buzzer. The door does not open because of feedback. Only the server user can publish it.

```json
{ "schema": 1, "id": "<read id>", "ts": 1794582241, "granted": true, "reason": "ok" }
```

**Local decision** `door/reader/local`. Sent when the Pico decided itself. `open_id` is the open-command id it published, or `null` when it approved the tag and could not reach the actuator in time.

```json
{
  "schema": 1,
  "id": "<read id>",
  "ts": 1794582242,
  "uid": "A1B2C3D4",
  "device": "entrance",
  "granted": true,
  "reason": "offline_ok",
  "allowlist_version": 3,
  "open_id": "<32 hex or null>"
}
```

**Log batch** `door/reader/log`. `ts` is when the batch was uploaded. Each entry keeps the original event `ts`. The server deduplicates on entry `id`.

**Allowlist** `door/reader/allowlist`, retained. Republished when tags change, when the server starts, and once a day so `utc_offset_min` follows daylight saving.

```json
{
  "schema": 1,
  "id": "<32 hex>",
  "ts": 1731510300,
  "version": 3,
  "hash": "hmac-sha256",
  "utc_offset_min": 120,
  "entries": [{ "h": "<64 hex>", "exp": 1893456000, "sch": "1-5,08:00-20:00" }]
}
```

Omit `exp` for no expiry. Omit `sch` for all hours. `exp` is absolute Unix time. `sch` is evaluated with `utc_offset_min` from this message. `open_ms` is the relay pulse, 200–10000. The Pico uses it for an offline grant and keeps the previous value when the field is missing. The Pico stores the message in flash and replaces it when `version` is greater than or equal to the stored version. `hash` must be `hmac-sha256`.

**Open** `door/actuator/open`. See the HMAC section. `source` is `server` or `reader`. `reason` is `tag`, `manual`, or `offline`.

**Result** `door/actuator/result`. `id` is the command id.

```json
{ "schema": 1, "id": "<command id>", "ts": 1731510242, "ok": true, "reason": "opened", "duration_ms": 3000 }
```

The access log keeps the decision reason (`ok`, `manual`, `offline_ok`, …). The server attaches `result.reason` when a result with that id arrives.

**Status**, retained, every 30 seconds. Reader example adds `ssid`, `allowlist_version`, and `log_queued`. Actuator example adds `relay` as `off` or `on`.

**Wi-Fi** `door/reader/wifi`, not retained. The server publishes it and the reader subscribes. The password crosses the LAN once and is not stored on the broker or the Pi. `ssid` is 1–32 characters. `password` is empty for an open network, or 8–63 characters. `setup_password` is 8–63 characters.

```json
{ "schema": 1, "id": "<32 hex>", "ts": 1794582240, "action": "set", "ssid": "home", "password": "secret" }
```

```json
{ "schema": 1, "id": "<32 hex>", "ts": 1794582240, "action": "forget", "setup_password": "ABCD234567" }
```

`set` joins the new network and, if that fails, joins the previous one again. `forget` clears the saved network and starts an access point named `Door-Setup` for 10 minutes. A phone on that network opens `http://192.168.4.1`. `scan` asks the reader to look for networks. The next status includes `scan_id` (the command id) and `networks`, a list of `{ "ssid", "rssi", "secure" }`. That list is not kept in later heartbeats.

**Last Will**, set before connect, QoS 1, retained, on that device’s status topic. The payload is exactly these bytes, with no spaces and no newline:

```text
{"online":false,"reason":"lwt"}
```

The broker publishes it after an unexpected disconnect. A new online status replaces it.

## HMAC

Keys from `openssl rand -hex 32` are 64 hex characters. The HMAC key is the **decoded 32 bytes**, not the ASCII hex text. The same rule is used for both keys.

Open command, UTF-8, no spaces:

```text
v1|{id}|{ts}|{nonce}|{duration_ms}|{source}|{reason}
```

`mac` is lowercase hex of HMAC-SHA256 over that string. Integers have no leading zeros. The worked example is `contract/examples/vectors.json` (public test key, never deploy it).

Allowlist entry:

```text
h = HMAC-SHA256(allowlist_key, uppercase UID)
```

The UID is normalized first: strip colons and spaces, uppercase. `A1:B2:C3:D4` and `A1B2C3D4` are the same tag.

Who holds which secret:

| Secret | Server | Pico | ESP-01 |
|---|---|---|---|
| MQTT password | its own | its own | its own |
| `DOOR_HMAC_SECRET` | yes | yes | yes |
| `ALLOWLIST_HMAC_KEY` | yes | yes | no |

The actuator checks a command in this order:

1. `malformed` — schema, types, id, nonce, source, or reason
2. `bad_mac` — constant-time compare
3. `time_unsynced` — the actuator has no NTP time yet
4. `replay` — nonce is in the flash ring
5. `stale` — `ts` is more than 30 seconds from the actuator clock
6. `duration` — outside 200–10000 ms
7. `busy` — a pulse is already running (the nonce is not spent, so this command can still be used until it goes stale)
8. `opened` — the nonce is stored, then the relay is pulsed

## Schedules

`sch` is `days,HH:MM-HH:MM`. Days are ISO weekdays, Monday `1` through Sunday `7`: `*`, a list `1,3,5`, or an inclusive range `1-5`. Ranges and lists can mix: `1-5,7`.

Local time is `ts + utc_offset_min * 60`, then read as a civil clock. The weekday math is floor division of that local instant, with a positive remainder, anchored on Thursday 1970-01-01. The start minute is inside the window. The end minute is outside it. `22:00-06:00` crosses midnight. `08:00-08:00` matches nothing. A full day is an omitted `sch`.

A broken `sch` does not grant. Disabled tags are left out of the allowlist, so the Pico reports `unknown` for them. The server, online, reports `disabled`.

## Who decides

1. The Pico publishes `door/reader/uid` and waits 1200 ms for feedback with the same id.
2. If feedback arrives, it shows the result and does not send an open command. On a grant, the server publishes `door/actuator/open` and writes the log.
3. If feedback does not arrive and the Pico has NTP, it checks the cached allowlist and publishes `door/reader/local`. On a grant it also publishes a signed open command.
4. If the broker connection is down, it still evaluates the allowlist and appends the event to the flash log. It holds a signed open command only until `ts + 30`. If the broker returns inside that window, it publishes the command. After 30 seconds it drops the command, stores reason `not_actuated`, and the door stays closed.
5. With no NTP time, the offline result is `time_unsynced` and the door stays closed. The Pico has no battery-backed clock, so the first decision after power returns needs Wi-Fi and NTP even when a cached allowlist is present.
6. On reconnect it uploads queued logs in batches and clears a batch only after the broker accepts it.
7. If the server and the Pico both publish an open for the same tap, the actuator pulses once. The second command receives `busy` while the pulse is running. The server skips its own open when a local decision for that read id arrives with `open_id` set.

| What failed | Door | What is recorded |
|---|---|---|
| Server down, broker up | Opens from the cached allowlist | `door/reader/local`, filed when the server returns |
| Broker down | Stays closed. The actuator only listens on MQTT | Flash log, uploaded with the original timestamps |
| Wi-Fi down | Stays closed | Same flash log, if a clock was synced earlier |
| Pico off | Stays closed | Reader status goes offline |
| Actuator off or rebooting | Stays closed | Nothing waits on the broker to open it later |

## Reasons

Decision reasons: `ok`, `offline_ok`, `manual`, `unknown`, `disabled`, `expired`, `outside_hours`, `time_unsynced`, `not_actuated`.

Command reasons: `tag`, `manual`, `offline`.

Actuator reasons: `opened`, `malformed`, `bad_mac`, `time_unsynced`, `replay`, `stale`, `duration`, `busy`.

## Broker access

`contract/mosquitto/acl`:

| User | May subscribe | May publish |
|---|---|---|
| `door-reader` | allowlist, feedback, wifi | uid, local, log, reader status, **and** `door/actuator/open` |
| `door-actuator` | open | actuator status, result |
| `door-server` | `door/#` | `door/#` |

The reader may publish open commands so offline mode works. That password alone cannot forge one. The HMAC key is not on the wire.

Run this on the Pi. `mosquitto_passwd -c` **replaces** an existing password file.

```bash
sudo mosquitto_passwd -c /etc/mosquitto/passwd door-reader
sudo mosquitto_passwd    /etc/mosquitto/passwd door-actuator
sudo mosquitto_passwd    /etc/mosquitto/passwd door-server
sudo chown root:mosquitto /etc/mosquitto/passwd
sudo chmod 640 /etc/mosquitto/passwd

sudo install -m 640 -o root -g mosquitto contract/mosquitto/acl /etc/mosquitto/acl
sudo install -m 644 contract/mosquitto/mosquitto.conf.example /etc/mosquitto/conf.d/door.conf
sudo systemctl reload mosquitto
```

Generate the two HMAC keys once. They are not the MQTT passwords.

```bash
openssl rand -hex 32
```

`listener 1883` in the example accepts devices on the LAN. Do not forward that port from the router. If Mosquitto fails to start because port 1883 is already configured, keep a single `listener` line and leave `allow_anonymous false`, `password_file`, and `acl_file` in `conf.d/door.conf`.

The server connects to `127.0.0.1`, so its MQTT password stays on the Pi. The reader and actuator passwords cross the LAN until TLS is turned on. The commented `listener 8883` block is there for later. Open-command integrity does not wait for TLS.

## Tests

No broker and no hardware:

```bash
node tools/self-test.js
```

Print a normalized read:

```bash
node tools/sim-read.js --dry-run A1:B2:C3:D4
```

Stdout is JSON with `"uid":"A1B2C3D4"`.

Reproduce the signed vector (this prints, it does not publish):

```bash
export DOOR_HMAC_SECRET=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
node tools/sign-open.js --verify contract/examples/open.json
node tools/sign-open.js \
  --id aa11bb22cc33dd44ee55ff6677889900 \
  --nonce 00112233445566778899aabbccddeeff \
  --ts 1731510242 --source server --reason manual --duration 3000
```

The printed `mac` is `fc4ae0a23cf007148c2069ff620905394979b36dc8cb9bcca4cabab469341402`.

With Mosquitto loaded as above, in one terminal:

```bash
mosquitto_sub -h 127.0.0.1 -p 1883 -u door-server -P 'SERVER_PASSWORD' -t 'door/#' -v
```

In another:

```bash
MQTT_HOST=127.0.0.1 MQTT_USER=door-reader MQTT_PASS='READER_PASSWORD' \
  node tools/sim-read.js A1B2C3D4
```

The subscriber shows `door/reader/uid` and the JSON. Then confirm the ACL. Each of these must fail (the broker closes the connection, or the subscribe is refused):

```bash
mosquitto_pub -h 127.0.0.1 -u door-reader -P 'READER_PASSWORD' \
  -t door/actuator/status -m '{"online":true}'
mosquitto_pub -h 127.0.0.1 -u door-actuator -P 'ACTUATOR_PASSWORD' \
  -t door/reader/uid -m '{}'
mosquitto_sub -h 127.0.0.1 -u door-actuator -P 'ACTUATOR_PASSWORD' \
  -t door/reader/allowlist
```

Retained allowlist, using the server user:

```bash
mosquitto_pub -h 127.0.0.1 -u door-server -P 'SERVER_PASSWORD' \
  -t door/reader/allowlist -r -f contract/examples/allowlist.json
mosquitto_sub -h 127.0.0.1 -u door-reader -P 'READER_PASSWORD' \
  -t door/reader/allowlist -C 1
```

The reader receives the file immediately, then the command exits (`-C 1`).

Open commands are not retained. Do this with the ESP-01 unplugged, or with the relay disconnected from the buzzer. `--publish` is a real open command if an actuator is listening.

```bash
mosquitto_sub -h 127.0.0.1 -u door-actuator -P 'ACTUATOR_PASSWORD' \
  -t door/actuator/open -v
```

```bash
DOOR_HMAC_SECRET='YOUR_REAL_KEY' \
MQTT_HOST=127.0.0.1 MQTT_USER=door-server MQTT_PASS='SERVER_PASSWORD' \
  node tools/sign-open.js --publish --source server --reason manual
```

Stop the subscriber. Subscribe again for two seconds. Nothing should arrive, because the command was not retained:

```bash
mosquitto_sub -h 127.0.0.1 -u door-actuator -P 'ACTUATOR_PASSWORD' \
  -t door/actuator/open -W 2
```
