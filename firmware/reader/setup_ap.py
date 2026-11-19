# Setup access point. A phone joins Door-Setup and opens http://192.168.4.1.
# The point runs only while the caller is in this function, then it is turned off.

import network
import select
import socket

try:
    import time as _time
    ticks_ms = _time.ticks_ms
    ticks_diff = _time.ticks_diff
    ticks_add = _time.ticks_add
except AttributeError:
    import time as _time

    def ticks_ms():
        return int(_time.time() * 1000)

    def ticks_diff(a, b):
        return a - b

    def ticks_add(a, b):
        return a + b


AP_SSID = "Door-Setup"
AP_IP = "192.168.4.1"
AP_ADDR = (192, 168, 4, 1)


def _printable(value):
    for ch in value:
        code = ord(ch)
        if code < 32 or code == 127:
            return False
    return True


def credentials_ok(ssid, password):
    if not isinstance(ssid, str) or not isinstance(password, str):
        return False
    if not ssid or len(ssid) > 32 or not _printable(ssid):
        return False
    if not password:
        return True
    return 8 <= len(password) <= 63 and _printable(password)


def _unquote(raw):
    text = raw.replace("+", " ")
    out = bytearray()
    i = 0
    data = text.encode()
    while i < len(data):
        if data[i] == 37 and i + 2 < len(data):
            try:
                out.append(int(data[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.append(data[i])
        i += 1
    return out.decode()


def _form(body):
    fields = {}
    try:
        text = body.decode()
    except (UnicodeError, AttributeError):
        return fields
    for pair in text.split("&"):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        fields[_unquote(key)] = _unquote(value)
    return fields


def _esc(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def nearby_networks(wlan=None):
    if wlan is None:
        wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    try:
        rows = wlan.scan()
    except OSError as err:
        print("scan", err)
        return []
    seen = {}
    for row in rows:
        if not row:
            continue
        name = row[0]
        if isinstance(name, bytes):
            try:
                name = name.decode()
            except UnicodeError:
                continue
        if not isinstance(name, str) or not name or len(name) > 32:
            continue
        rssi = row[3] if len(row) > 3 else 0
        if isinstance(rssi, bool) or not isinstance(rssi, int):
            rssi = 0
        secure = True
        if len(row) > 4 and row[4] == 0:
            secure = False
        prev = seen.get(name)
        if prev is None or rssi > prev["rssi"]:
            seen[name] = {"ssid": name, "rssi": rssi, "secure": secure}
    found = list(seen.values())
    found.sort(key=lambda item: item["rssi"], reverse=True)
    return found[:15]


def _page(notice, networks):
    note = "<p>" + _esc(notice) + "</p>" if notice else ""
    choices = []
    for item in networks:
        label = _esc(item.get("ssid", ""))
        rssi = item.get("rssi")
        if isinstance(rssi, int) and not isinstance(rssi, bool):
            label += " (" + str(rssi) + " dBm)"
        if item.get("secure") is False:
            label += ", open"
        choices.append(
            '<label class="net"><input type="radio" name="pick" value="'
            + _esc(item.get("ssid", "")) + '"> ' + label + "</label>"
        )
    if choices:
        listing = "<p>Choose a network:</p>" + "".join(choices)
    else:
        listing = "<p>No networks found. Scan again, or type the name.</p>"
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Door reader Wi-Fi</title>"
        "<style>label.net{display:block;margin:.4rem 0}</style></head><body>"
        "<h1>Door reader Wi-Fi</h1>"
        + note
        + '<p><a href="/?rescan=1">Scan again</a></p>'
        + '<form method="post" action="/">'
        + listing
        + '<p><label>Hidden network<br><input name="other" maxlength="32"></label></p>'
        + '<p><label>Password<br><input name="password" type="password" maxlength="63"></label></p>'
        + '<p><button type="submit">Save and connect</button></p>'
        + "</form>"
        + "<p>Use at least 8 characters. Leave the password empty only for an open network.</p>"
        + "</body></html>"
    )


def _done_page():
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Saved</title></head><body>"
        "<h1>Saved</h1>"
        "<p>The reader is joining that network. Reconnect this phone to the home Wi-Fi.</p>"
        "</body></html>"
    )


def _send(conn, status, html):
    raw = html.encode()
    head = (
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %s\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n\r\n"
    ) % (status, len(raw))
    conn.send(head.encode() + raw)


def _read_http(conn):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 2048:
        chunk = conn.recv(256)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                length = 0
    if length > 300 or length < 0:
        length = 0
    while len(rest) < length:
        chunk = conn.recv(256)
        if not chunk:
            break
        rest += chunk
    return head, rest[:length]


def _dns_reply(packet):
    if len(packet) < 12 or len(packet) > 512:
        return None
    header = packet[:2] + b"\x81\x80" + packet[4:6] + packet[4:6] + b"\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(AP_ADDR)
    return header + packet[12:] + answer


def _config_ap(ap, password):
    if password and len(password) >= 8:
        try:
            ap.config(ssid=AP_SSID, password=password)
        except TypeError:
            ap.config(essid=AP_SSID, password=password)
        return
    try:
        ap.config(ssid=AP_SSID, security=0)
    except TypeError:
        ap.config(essid=AP_SSID, security=0)


def _start(password):
    ap = network.WLAN(network.AP_IF)
    ap.active(False)
    _config_ap(ap, password)
    ap.active(True)
    try:
        ap.ifconfig((AP_IP, "255.255.255.0", AP_IP, AP_IP))
    except OSError as err:
        print("setup ip", err)
    print("setup", AP_SSID, AP_IP)
    return ap


def _close(sock):
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def serve(ui, timeout_s, setup_password, notice=""):
    # Returns (ssid, password) or None when the window ends.
    if timeout_s < 1:
        return None
    ap = _start(setup_password)
    http = None
    dns = None
    try:
        http = socket.socket()
        http.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        http.bind(("0.0.0.0", 80))
        http.listen(1)
        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        dns.bind(("0.0.0.0", 53))
        poller = select.poll()
        poller.register(http, select.POLLIN)
        poller.register(dns, select.POLLIN)
        deadline = ticks_add(ticks_ms(), int(timeout_s) * 1000)
        message = notice
        networks = None
        while ticks_diff(deadline, ticks_ms()) > 0:
            if ui is not None:
                ui.set_both(((ticks_ms() // 500) & 1) == 0)
            wait = ticks_diff(deadline, ticks_ms())
            if wait > 400:
                wait = 400
            if wait < 1:
                break
            for obj, _event in poller.poll(wait):
                if obj is dns:
                    try:
                        packet, addr = dns.recvfrom(512)
                    except OSError:
                        continue
                    reply = _dns_reply(packet)
                    if reply:
                        try:
                            dns.sendto(reply, addr)
                        except OSError:
                            pass
                    continue
                try:
                    conn, _addr = http.accept()
                except OSError:
                    continue
                try:
                    conn.settimeout(3)
                    head, body = _read_http(conn)
                    line = head.split(b"\r\n", 1)[0]
                    parts = line.split(b" ")
                    method = parts[0] if parts else b""
                    target = parts[1] if len(parts) > 1 else b"/"
                    if networks is None or (method == b"GET" and b"rescan=1" in target):
                        networks = nearby_networks()
                    if method == b"POST":
                        fields = _form(body)
                        typed = fields.get("other", "").strip()
                        ssid = typed or fields.get("pick", "")
                        password = fields.get("password", "")
                        if credentials_ok(ssid, password):
                            _send(conn, "200 OK", _done_page())
                            return ssid, password
                        message = "Choose a network, and use a password of at least 8 characters."
                    _send(conn, "200 OK", _page(message, networks))
                except Exception as err:
                    print("setup", err)
                finally:
                    _close(conn)
        return None
    except OSError as err:
        print("setup", err)
        return None
    finally:
        _close(http)
        _close(dns)
        try:
            ap.active(False)
        except OSError:
            pass
