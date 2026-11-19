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

Copy `include/secrets.example.h` to `include/secrets.h`. Set the home Wi-Fi, the `door-actuator` MQTT password, and `DOOR_HMAC_SECRET` from the Pi. `MQTT_HOST` is the Pi's LAN address.

From this folder:

```bash
pio run -e esp01_1m -t upload --upload-port /dev/cu.usbserial-240
```

The log is 115200. The first line is `door-actuator 0.1.0`. If that line never appears, GPIO0 is still grounded: release it and reset the module.

The Live page shows the door relay online after the board joins Wi-Fi and Mosquitto. A granted tag or Open now pulses GPIO2. Do that with the relay disconnected from the buzzer until the wiring is checked.
