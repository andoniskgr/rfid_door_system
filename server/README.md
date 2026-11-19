# Door access server

Node.js app for the Raspberry Pi. It checks tag reads, keeps the SQLite log, publishes the hashed allowlist, and sends signed open commands. The browser is meant to be reached through Tailscale Serve, with the process bound to `127.0.0.1`.

## Run the tests

From `server/`:

```bash
npm install
npm test
```

The tests use a temporary database and a fake MQTT connection. They cover setup and TOTP login, password change and recovery, lockout, a simulated UID read, offline log upload, manual open, reader Wi-Fi changes, Telegram toggles, the CSV export, and the live WebSocket.

## Configure

```bash
cp .env.example .env
openssl rand -hex 32   # SESSION_SECRET
openssl rand -hex 32   # DOOR_HMAC_SECRET, also goes in both devices
openssl rand -hex 32   # ALLOWLIST_HMAC_KEY, also goes in the Pico
```

`MQTT_PASS` is the `door-server` password from the [broker setup](../contract/README.md). Leave the Telegram variables empty until you want messages. Each notification can also be turned off under Settings.

`COOKIE_SECURE=true` is for HTTPS. `tailscale serve` provides that. Use `COOKIE_SECURE=false` only when trying the app over plain `http://127.0.0.1`.

```bash
cd server
npm start
```

`npm start` from the repo root does the same thing. Either way, `server/.env` is read first. A variable already set in the shell is left as it is.

The first start prints a setup token to that terminal (journald, once the service is installed). Open the app, enter that token, choose a username and a password of at least 12 characters, then confirm the authenticator code. The token expires after 30 minutes. Restart the process to print another one. There is no default password.

Five failed logins from one address in 15 minutes are refused. Ten failed logins lock the account for 15 minutes.

## Password

Change it under Settings while logged in. Enter the current password, a new password of at least 12 characters, and the authenticator code. Other browsers are signed out.

If the password is forgotten, open **Forgot the password?** on the log-in page. Enter a new password and the authenticator code. Every session is signed out. Restarting the service does not reset the password.

## Install on the Pi

```bash
sudo useradd --system --create-home --home-dir /opt/door --shell /usr/sbin/nologin door
sudo mkdir -p /opt/door
sudo rsync -a --exclude node_modules --exclude data ./ /opt/door/
sudo chown -R door:door /opt/door
sudo -u door bash -lc 'cd /opt/door/server && npm install --omit=dev'
sudo cp server/systemd/door-access.service /etc/systemd/system/door-access.service
# Edit ExecStart if `command -v node` is not /usr/bin/node.
sudo systemctl daemon-reload
sudo systemctl enable --now door-access
sudo journalctl -u door-access -n 50
```

Publish it on the tailnet and leave port 3000 closed to everything else:

```bash
sudo tailscale serve --bg http://127.0.0.1:3000
```

Check the listener:

```bash
ss -ltnp | grep 3000
```

It should show `127.0.0.1:3000`.

A database backup is written to `data/backups/` once a day, the first time the process is running after 03:00 in `TZ`. Fourteen copies are kept. The allowlist is published again after 03:05, and also whenever tags change or the UTC offset changes.

## Reader Wi-Fi

Settings can send the entrance reader a new network, or clear the saved one. The reader has to be online and on firmware 0.2.0 or newer. The home Wi-Fi password is published once on `door/reader/wifi` and is not stored on the Pi. A wrong password leaves the reader on its current network.

Reset starts a 10-minute `Door-Setup` network at the door. The page shows the password for that network and the address to open on a phone, `http://192.168.4.1`. Install the updated broker ACL before using this, or the reader is not allowed to subscribe to the command.

## Try a read without hardware

With the server and Mosquitto running, and the broker ACL installed:

```bash
MQTT_HOST=127.0.0.1 MQTT_USER=door-reader MQTT_PASS='READER_PASSWORD' \
  node ../tools/sim-read.js A1B2C3D4
```

The Live page shows the UID as denied until you register it under Tags. Registering publishes the retained allowlist. The next simulated read is granted and a signed `door/actuator/open` goes out. Do that with the ESP-01 unplugged, or with the relay off the buzzer.

Open now asks for confirmation and is stored as a manual open. It sends a real pulse when the actuator is connected.

## Notifications

Unknown tag, repeated denies (3 for the same UID within 10 minutes, then quiet for 30 minutes), reader or relay online/offline, and manual open. The same UID is reported as unknown at most once per 10 minutes. The first status message after install sets the baseline and does not notify. Later changes do.
