# Pico W reader

MicroPython for the entrance reader. It reads a MIFARE UID from the RC522, publishes `door/reader/uid`, and waits 1.2 seconds for the server. If the server answers, the LED and buzzer follow that answer and the Pico does not send an open command. If the server does not answer, the Pico uses the cached allowlist. A local grant publishes a signed `door/actuator/open`. Nothing pulses the relay until the ESP-01 is running.

The same UID is ignored for 2 seconds. A retained status is published every 30 seconds. The last will is `{"online":false,"reason":"lwt"}`. While the broker is down, decisions are stored on the Pico and uploaded in batches after it reconnects. A signed open is kept for 30 seconds and then dropped.

## Wiring

The RC522 uses 3.3 V, not 5 V.

| Signal | Pico |
|---|---|
| SCK | GP6 |
| MOSI | GP7 |
| MISO | GP4 |
| SDA | GP5 |
| RST | GP22 |
| LED green | GP16 |
| LED red | GP17 |
| Buzzer | GP18 |
| Setup button, optional | GP15 to GND |

The LEDs and the buzzer are active high. GP18 is driven with a tone, so a passive piezo or an active buzzer both make a sound.

## Flash

Install the Pico W MicroPython UF2 if the board does not already have it. Copy every `.py` file in this folder except `check_policy.py` and `secrets.example.py` onto the Pico. `secrets.py` is the one that must be edited first: set `WIFI_SSID` and `WIFI_PASSWORD`. That pair is only the first network. After the reader is online, change it from the server Settings page. The MQTT password and both HMAC keys in that file match the Pi. `MQTT_HOST` is the Pi's LAN address, `192.168.2.31`.

From this folder, with the Pico plugged into USB:

```bash
python3 check_policy.py
mpremote cp pins.py crypto_util.py policy.py mqtt_client.py mfrc522.py store.py wifi_store.py setup_ap.py ui.py secrets.py main.py :
mpremote reset
```

Thonny can save the same files to the board instead. `main.py` runs on power-up. Firmware `0.3.0` scans for networks and can change Wi-Fi without another copy. An offline grant uses `open_ms` from the allowlist when the server has published one. `OPEN_MS` in `secrets.py` is the fallback until then.

Reload Mosquitto after installing the ACL in `contract/mosquitto/acl`. The reader has to be allowed to subscribe to `door/reader/wifi`, or the Settings page can send a network the Pico never receives.

## Change Wi-Fi

Settings, while the reader is online, can scan and list the networks the Pico can see. Choose one and enter its password. The Pico stores the choice in `/wifi.json` and joins. If the new network refuses the join, it goes back to the previous one. The password is not kept on the Pi. The setup page at `http://192.168.4.1` shows the same kind of list, with a Scan again link.

Reset Wi-Fi clears `/wifi.json` and the Pico broadcasts `Door-Setup` for 10 minutes. The page shows a one-time password. Join that network from a phone, open `http://192.168.4.1`, and enter the new network. Then put the phone back on the home Wi-Fi.

The same setup page opens in two other cases. Hold a button wired from GP15 to GND for 3 seconds. The current network is kept if you do not save a new one. Leave GP15 unconnected when there is no button. A power-cycle with no saved network also opens `Door-Setup` for 10 minutes. That one uses `SETUP_AP_PASSWORD` from `secrets.py` when it is at least 8 characters, and is open when that line is empty. A router reboot does not open the setup network. The reader keeps retrying the saved one.

A tap of an unknown card shows on the Live page as denied, and MQTT Explorer shows `door/reader/uid` plus a retained `door/reader/status`. Register the card under Tags. The next tap is granted. The open command is visible on `door/actuator/open` and does not move the lock until the actuator is installed.
