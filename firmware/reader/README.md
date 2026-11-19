# Pico W reader

MicroPython for the entrance reader. It reads a MIFARE UID from the RC522, publishes `door/reader/uid`, and waits 1.2 seconds for the server. If the server answers, the LED and buzzer follow that answer and the Pico does not send an open command. If the server does not answer, the Pico uses the cached allowlist. A local grant publishes a signed `door/actuator/open`. Nothing pulses the relay until the ESP-01 is running.

The same UID is ignored for 2 seconds. A retained status is published every 30 seconds. The last will is `{"online":false,"reason":"lwt"}`. While the broker is down, decisions are stored on the Pico and uploaded in batches after it reconnects. A signed open is kept for 30 seconds and then dropped.

## Wiring

The RC522 uses 3.3 V, not 5 V.

| RC522 | Pico |
|---|---|
| SCK | GP6 |
| MOSI | GP7 |
| MISO | GP4 |
| SDA | GP5 |
| RST | GP22 |
| LED green | GP16 |
| LED red | GP17 |
| Buzzer | GP18 |

The LEDs and the buzzer are active high. GP18 is driven with a tone, so a passive piezo or an active buzzer both make a sound.

## Flash

Install the Pico W MicroPython UF2 if the board does not already have it. Copy every `.py` file in this folder except `check_policy.py` and `secrets.example.py` onto the Pico. `secrets.py` is the one that must be edited first: set `WIFI_SSID` and `WIFI_PASSWORD`. The MQTT password and both HMAC keys in that file match the Pi. `MQTT_HOST` is the Pi's LAN address, `192.168.2.31`.

From this folder, with the Pico plugged into USB:

```bash
python3 check_policy.py
mpremote cp pins.py crypto_util.py policy.py mqtt_client.py mfrc522.py store.py ui.py secrets.py main.py :
mpremote reset
```

Thonny can save the same files to the board instead. `main.py` runs on power-up.

A tap of an unknown card shows on the Live page as denied, and MQTT Explorer shows `door/reader/uid` plus a retained `door/reader/status`. Register the card under Tags. The next tap is granted. The open command is visible on `door/actuator/open` and does not move the lock until the actuator is installed.
