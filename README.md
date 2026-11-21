# RFID door access

Apartment door access for one entrance. A Pico W reads a MIFARE UID, a Raspberry Pi decides, and an ESP-01 pulses the buzzer relay. All three talk MQTT on the home LAN. The web app is reached through Tailscale.

| Piece | Where | State |
|---|---|---|
| MQTT contract, ACL, simulators | `contract/`, `tools/` | in the tree |
| Server (Node.js, Express, SQLite) | `server/` | in the tree |
| Actuator firmware (ESP-01, PlatformIO) | `firmware/actuator/` | in the tree |
| Reader firmware (Pico W, MicroPython) | `firmware/reader/` | in the tree |

The wire rules and the no-hardware tests are in [contract/README.md](contract/README.md).

## How a tap is handled

The Pico sleeps with Wi-Fi off until a card is read or its 10-minute check-in. It then publishes the UID and waits 1.2 seconds. If the server answers, the server decides and, on a grant, sends a signed open command to the ESP-01. If the server does not answer, the Pico checks a cached allowlist of HMAC-SHA256 UID hashes and can send that open command itself. The allowlist is a retained MQTT message, versioned, and refreshed when tags change.

The ESP-01 pulses a relay for the time set under Settings (3 seconds until you change it, hard maximum 10). It rejects stale, replayed, and badly signed commands. The relay is active-low on GPIO2 with an external pull-up, and the buzzer is wired on the normally open contact, so a reset or a power loss leaves the door locked.

Secrets stay in `secrets.py` / `secrets.h` and the server environment. Those files are gitignored.

## When the broker is down

The actuator only hears open commands over MQTT. There is no second radio path.

| What failed | Door | Record |
|---|---|---|
| Server down, broker up | Opens from the Pico's cached allowlist | Uploaded as a local decision |
| Broker down | Stays closed | Pico keeps a flash log and uploads it with the original timestamps |
| Wi-Fi down | Stays closed | Same flash log, once a clock was synced before the outage |
| Actuator down | Stays closed | An open command is not waiting for it to reconnect |

A signed open command older than 30 seconds is discarded. The door does not open minutes later when the broker returns. The person presents the tag again.

## Security limits

This checks that a UID is on a list. A MIFARE UID can be copied onto a blank card after a few seconds next to the original, and the door will accept the copy.

The allowlist stores HMAC-SHA256 of the UID, not the UID itself, so a casual dump of the Pico flash does not list the tags. A 4-byte UID is still brute-forceable by someone who also has `ALLOWLIST_HMAC_KEY`. That key is on the Pico, in plaintext MicroPython files. Physical access to the Pico yields the MQTT password and both HMAC keys, which is enough to open the door.

Without TLS, the reader and actuator MQTT passwords are visible to anyone who can watch the LAN. A captured reader password can inject a UID. Combined with a UID that is already enrolled, the server will open the door. A captured actuator password can publish a fake status. It cannot produce a valid open-command MAC. The server's own MQTT password stays on the Pi (`127.0.0.1`). TLS is described in the contract and left off until the ESP-01 heap is measured. Do not expose port 1883 past the home LAN.

The upgrade path, when the UID check is no longer enough, is MIFARE DESFire EV2 or EV3 with AES challenge-response: the Pico sends a proof from the card instead of a bare UID. Offline mode then has to hold application keys. That is a later contract (`schema` 2).

## Layout

```text
contract/     MQTT topics, ACL, examples, reference decisions
tools/        sim-read.js, sign-open.js, self-test.js
firmware/     reader (MicroPython); actuator (PlatformIO, ESP-01)
server/       web app, SQLite, MQTT client
```

Check the contract without hardware:

```bash
node tools/self-test.js
```
