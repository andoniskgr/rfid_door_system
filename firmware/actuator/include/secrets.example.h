#pragma once

// Copy to secrets.h. secrets.h is gitignored.
// WIFI_* is the home network. MQTT_USER is door-actuator.
// DOOR_HMAC_SECRET is the 64 hex characters from the Pi, decoded as 32 bytes.

#define WIFI_SSID "your-wifi"
#define WIFI_PASSWORD "your-wifi-password"
#define MQTT_HOST "192.168.2.31"
#define MQTT_PORT 1883
#define MQTT_USER "door-actuator"
#define MQTT_PASS "actuator-mqtt-password"
#define DOOR_HMAC_SECRET "0000000000000000000000000000000000000000000000000000000000000000"
