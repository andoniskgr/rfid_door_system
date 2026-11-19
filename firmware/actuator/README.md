# ESP-01 actuator

The actuator listens for `door/actuator/open` and pulses a relay. The relay is active-low on GPIO2, with an external pull-up. Idle is high, so a reset or a power loss leaves the door locked. The buzzer is on the normally open contact.

A command is accepted only when the HMAC matches, NTP time is set, the nonce is new, `ts` is within 30 seconds, and the pulse length is from 200 to 10000 ms. A second command during a pulse gets `busy` and does not spend its nonce. The hard maximum is compiled in.

Status is retained on `door/actuator/status` every 30 seconds. The last will is `{"online":false,"reason":"lwt"}`.

## Wiring

3.3 V only. CH_PD (EN) stays at 3.3 V.

| Signal | ESP-01 |
|---|---|
| VCC, CH_PD | 3.3 V |
| GND | GND |
| GPIO2 | relay IN |

TX and RX go to the USB-UART adapter for flashing. GPIO0 is grounded only to enter the bootloader.

## Flash

Copy `include/secrets.example.h` to `include/secrets.h`. Set the home Wi-Fi, the `door-actuator` MQTT password, and `DOOR_HMAC_SECRET` from the Pi. `MQTT_HOST` is the Pi's LAN address. `WIFI_SSID` is only the first network. After the actuator is online, change it from the server Settings page. `SETUP_AP_PASSWORD` is optional.

From this folder:

```bash
pio run -e esp01_1m -t upload --upload-port /dev/cu.usbserial-240
```

The log is 115200. The first line is `door-actuator 0.2.0`. If that line never appears, GPIO0 is still grounded: release it and reset the module.

Reload Mosquitto after installing the ACL in `contract/mosquitto/acl`. The actuator has to be allowed to subscribe to `door/actuator/wifi`, or the Settings page can send a network the ESP-01 never receives.

## Change Wi-Fi

Settings, while the actuator is online, can scan and list the networks the ESP-01 can see. Choose one and enter its password. The board stores the choice in flash and joins. If the new network refuses the join, it goes back to the previous one. The password is not kept on the Pi. The setup page at `http://192.168.4.1` shows the same kind of list, with a Scan again link. Firmware older than `0.2.0` has to be reflashed before this works.

Reset Wi-Fi clears the saved network and the ESP-01 broadcasts `Actuator-Setup` for 10 minutes. The page shows a one-time password. Join that network from a phone, open `http://192.168.4.1`, and enter the new network. The page waits until the actuator has an address. A wrong password stays on that page and says the network did not connect. When it shows the address, put the phone back on the home Wi-Fi.

The same setup page opens in two other cases. After the module is running, hold the FLASH button (GPIO0 to GND) for 3 seconds. The current network is kept if you do not save a new one. Do not hold FLASH while powering on: that enters the bootloader. A power-cycle with no saved network also opens `Actuator-Setup` for 10 minutes. That one uses `SETUP_AP_PASSWORD` from `secrets.h` when it is at least 8 characters, and is open when that line is empty or missing. A router reboot does not open the setup network. The actuator keeps retrying the saved one.

The Live page shows the door relay online after the board joins Wi-Fi and Mosquitto. A granted tag or Open now pulses GPIO2. Do that with the relay disconnected from the buzzer until the wiring is checked.
