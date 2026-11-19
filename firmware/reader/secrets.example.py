# Copy to secrets.py on the Pico. secrets.py is gitignored.

WIFI_SSID = ""
WIFI_PASSWORD = ""

# The Pi's LAN address. Mosquitto listens on 1883. Do not use the Tailscale address.
MQTT_HOST = "192.168.2.31"
MQTT_PORT = 1883
MQTT_USER = "door-reader"
MQTT_PASS = ""

# 64 hex characters each, the same values as server/.env.
DOOR_HMAC_SECRET = ""
ALLOWLIST_HMAC_KEY = ""

DEVICE = "entrance"
OPEN_MS = 3000
