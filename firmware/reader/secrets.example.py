# Copy to secrets.py on the Pico. secrets.py is gitignored.

# First network only. After that, change it from the server Settings page.
# A saved network on the Pico replaces these two lines.
WIFI_SSID = ""
WIFI_PASSWORD = ""

# Optional password for the Door-Setup network opened by the button or a
# power-cycle with no saved network. At least 8 characters, or empty for an open network.
SETUP_AP_PASSWORD = ""

# The Pi's LAN address. Mosquitto listens on 1883. Do not use the Tailscale address.
MQTT_HOST = "192.168.2.31"
MQTT_PORT = 1883
MQTT_USER = "door-reader"
MQTT_PASS = ""

# 64 hex characters each, the same values as server/.env.
DOOR_HMAC_SECRET = ""
ALLOWLIST_HMAC_KEY = ""

DEVICE = "entrance"
# Used for an offline grant until the allowlist includes open_ms from Settings.
OPEN_MS = 3000
