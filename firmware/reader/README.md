# Pico W reader

MicroPython for the entrance reader. It reads a MIFARE UID from the RC522, publishes `door/reader/uid`, and waits 1.2 seconds for the server. If the server answers, the LED and buzzer follow that answer and the Pico does not send an open command. If the server does not answer, the Pico uses the cached allowlist. A local grant publishes a signed `door/actuator/open`. Nothing pulses the relay until the ESP-01 is running.

The same UID is ignored for 2 seconds. Between taps the radio is off. A retained status, with `sleeping` set, is published on a tap and about every 10 minutes. The last will is `{"online":false,"reason":"lwt"}`, and a clean disconnect does not send it. While the broker is down, decisions are stored on the Pico and uploaded in batches the next time it connects. A signed open is kept for 30 seconds and then dropped.

## Wiring

The RC522 uses 3.3 V, not 5 V.

| Signal | Pico |
|---|---|
| SDA (chip select) | GP20 |
| SCK | GP21 |
| MOSI | GP26 |
| MISO | GP22 |
| IRQ | GP27 |
| RST | GP28 |
| LED green | GP16 |
| LED red | GP17 |
| Buzzer | GP18 |
| Setup button, optional | GP15 to GND |

The LEDs and the buzzer are active high. GP18 is driven with a tone, so a passive piezo or an active buzzer both make a sound.

## Power

A 12 V DC supply feeds the reader through a step-down converter set to 5 V. The converter’s 5 V output goes to Pico VSYS (pin 39), and its ground goes to Pico GND. VSYS must stay at or below 5.5 V, so 12 V never connects to the Pico. Do not feed the converter into 3V3. 3V3 is a regulator output. The Pico USB port is for programming.

The ESP-01 still needs 3.3 V. If this converter is the shared 5 V rail, use a 3.3 V regulator from that rail for the ESP-01. Do not put 5 V or 12 V on the ESP-01.

Firmware `0.6.0` turns Wi-Fi off between cards and holds the RC522 in reset so its antenna is off. It pauses for 300 ms, wakes, powers the reader just long enough to look for a card, then pauses again. A card chirps at once. Wi-Fi and MQTT come up after that, so the door usually opens a few seconds later than it did with the radio left on. It does not light-sleep, so the serial port stays up while the USB cable is plugged in.

The RC522 cannot see a card with the antenna off. IRQ is wired to GP27, and the firmware still polls, because the chip is held in reset between looks. A tap, or the 10-minute check-in, is what turns Wi-Fi on. That check-in refreshes the clock, the allowlist, and the saved log.

Settings shows the reader as online and “asleep until a card”. A scan or a Wi-Fi change from Settings is refused while it is asleep. Hold the setup button for 3 seconds to change the network. Restart the server with this tree before relying on the longer offline window. An older server still marks a silent reader offline after 90 seconds and will send a Telegram message each check-in.

## Flash

Install the Pico W MicroPython UF2 if the board does not already have it. Copy every `.py` file in this folder except `check_policy.py` and `secrets.example.py` onto the Pico. `secrets.py` is the one that must be edited first: set `WIFI_SSID` and `WIFI_PASSWORD`. That pair is only the first network. After the reader is online, change it from the server Settings page. The MQTT password and both HMAC keys in that file match the Pi. `MQTT_HOST` is the Pi's LAN address, `192.168.2.31`.

From this folder, with the Pico plugged into USB:

```bash
python3 check_policy.py
mpremote cp pins.py crypto_util.py policy.py mqtt_client.py mfrc522.py store.py wifi_store.py setup_ap.py ui.py secrets.py main.py :
mpremote reset
```

Thonny can save the same files to the board instead. `main.py` runs on power-up. Firmware `0.3.0` scans for networks and can change Wi-Fi without another copy. Firmware `0.5.0` turns Wi-Fi off between cards. Firmware `0.6.0` drops the cell and runs from the 5 V converter. Firmware `0.6.1` moves the RC522 to GP20, GP21, GP22, GP26, GP27, and GP28. Those SPI pins are bit-banged. Delete `battery.py` from the Pico if a previous copy left it there. An offline grant uses `open_ms` from the allowlist when the server has published one. `OPEN_MS` in `secrets.py` is the fallback until then.

Reload Mosquitto after installing the ACL in `contract/mosquitto/acl`. The reader has to be allowed to subscribe to `door/reader/wifi`, or the Settings page can send a network the Pico never receives.

## Change Wi-Fi

Settings, while the reader is on a check-in, can scan and list the networks the Pico can see. Firmware 0.5.0 is asleep between cards, and Settings refuses a scan or a network change until you hold the setup button. Choose one and enter its password. The Pico stores the choice in `/wifi.json` and joins. If the new network refuses the join, it goes back to the previous one. The password is not kept on the Pi. The setup page at `http://192.168.4.1` shows the same kind of list, with a Scan again link.

Reset Wi-Fi clears `/wifi.json` and the Pico broadcasts `Door-Setup` for 10 minutes. The page shows a one-time password. Join that network from a phone, open `http://192.168.4.1`, and enter the new network. Then put the phone back on the home Wi-Fi.

The same setup page opens in two other cases. Hold a button wired from GP15 to GND for 3 seconds. The current network is kept if you do not save a new one. Leave GP15 unconnected when there is no button. A power-cycle with no saved network also opens `Door-Setup` for 10 minutes. That one uses `SETUP_AP_PASSWORD` from `secrets.py` when it is at least 8 characters, and is open when that line is empty. A router reboot does not open the setup network. The reader keeps retrying the saved one.

A tap of an unknown card shows on the Live page as denied, and MQTT Explorer shows `door/reader/uid` plus a retained `door/reader/status`. Register the card under Tags. The next tap is granted. The open command is visible on `door/actuator/open` and does not move the lock until the actuator is installed.
