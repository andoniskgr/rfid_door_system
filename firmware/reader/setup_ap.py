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


def _page(notice):
    note = "<p>%s</p>" % notice if notice else ""
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Door reader Wi-Fi</title></head><body>"
        "<h1>Door reader Wi-Fi</h1>%s"
        "<form method=\"post\" action=\"/\">"
        "<p><label>Network name<br><input name=\"ssid\" maxlength=\"32\" required></label></p>"
        "<p><label>Password<br><input name=\"password\" type=\"password\" maxlength=\"63\"></label></p>"
        "<p><button type=\"submit\">Save and connect</button></p>"
        "</form>"
        "<p>Use at least 8 characters. Leave the password empty only for an open network.</p>"
        "</body></html>"
    ) % note


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
                    method = line.split(b" ", 1)[0] if line else b""
                    if method == b"POST":
                        fields = _form(body)
                        ssid = fields.get("ssid", "")
                        password = fields.get("password", "")
                        if credentials_ok(ssid, password):
                            _send(conn, "200 OK", _done_page())
                            return ssid, password
                        message = "Use a network name, and a password of at least 8 characters."
                    _send(conn, "200 OK", _page(message))
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
