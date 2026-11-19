# MQTT 3.1.1 for the reader. Clean session, QoS 1, keepalive 60.
# A PUBACK is required before a publish is treated as accepted.

try:
    import usocket as socket
except ImportError:
    import socket

try:
    import time as _time
    ticks_ms = _time.ticks_ms
    ticks_diff = _time.ticks_diff
    ticks_add = _time.ticks_add
    sleep_ms = _time.sleep_ms
except AttributeError:
    import time as _time

    def ticks_ms():
        return int(_time.time() * 1000)

    def ticks_diff(a, b):
        return a - b

    def ticks_add(a, b):
        return a + b

    def sleep_ms(ms):
        _time.sleep(ms / 1000.0)


LWT_TOPIC = "door/reader/status"
LWT_PAYLOAD = b'{"online":false,"reason":"lwt"}'


def _again(err):
    number = getattr(err, "errno", None)
    if number in (11, 35, 10035):
        return True
    text = str(err).lower()
    return "again" in text or "timed out" in text or "timeout" in text


def _utf8(value):
    raw = value.encode() if isinstance(value, str) else bytes(value)
    if len(raw) > 65535:
        raise ValueError("mqtt string too long")
    return bytes([(len(raw) >> 8) & 0xFF, len(raw) & 0xFF]) + raw


def _remaining(length):
    out = bytearray()
    left = length
    while True:
        digit = left % 128
        left //= 128
        if left:
            digit |= 0x80
        out.append(digit)
        if not left:
            return bytes(out)


def _packet(first, body):
    return bytes([first]) + _remaining(len(body)) + body


class MqttClient:
    def __init__(self, host, port, username, password, client_id="door-reader"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_id = client_id
        self.sock = None
        self.buf = b""
        self.packet_id = 0
        self.on_message = None
        self.connected = False
        self._last_io = 0

    def connect(self):
        self.close()
        info = socket.getaddrinfo(self.host, self.port)[0][-1]
        sock = socket.socket()
        try:
            try:
                sock.settimeout(10)
            except OSError:
                pass
            sock.connect(info)
        except OSError:
            sock.close()
            raise
        try:
            sock.setblocking(False)
        except OSError:
            sock.settimeout(0)
        self.sock = sock
        self.buf = b""
        # username, password, will retain, will QoS 1, will flag, clean session
        flags = 0x80 | 0x40 | 0x20 | 0x08 | 0x04 | 0x02
        body = b"".join([
            _utf8("MQTT"),
            bytes([0x04, flags, 0x00, 60]),
            _utf8(self.client_id),
            _utf8(LWT_TOPIC),
            _utf8(LWT_PAYLOAD),
            _utf8(self.username),
            _utf8(self.password),
        ])
        self._send(_packet(0x10, body))
        payload = self._wait_type(2, 8000)
        if payload is None or len(payload) < 2 or payload[1] != 0:
            self.close()
            code = payload[1] if payload and len(payload) > 1 else "none"
            raise OSError("mqtt connect refused: {}".format(code))
        self.connected = True
        self._last_io = ticks_ms()

    def subscribe(self, topics):
        self.packet_id = self.packet_id % 65535 + 1
        parts = [bytes([(self.packet_id >> 8) & 0xFF, self.packet_id & 0xFF])]
        for topic in topics:
            parts.append(_utf8(topic))
            parts.append(b"\x01")
        self._send(_packet(0x82, b"".join(parts)))
        payload = self._wait_type(9, 5000)
        if payload is None:
            raise OSError("mqtt subscribe was not acknowledged")

    def publish(self, topic, payload, retain=False):
        if not self.connected:
            return False
        if isinstance(payload, str):
            payload = payload.encode()
        self.packet_id = self.packet_id % 65535 + 1
        first = 0x32
        if retain:
            first |= 0x01
        body = _utf8(topic) + bytes([
            (self.packet_id >> 8) & 0xFF,
            self.packet_id & 0xFF,
        ]) + payload
        try:
            self._send(_packet(first, body))
            ack = self._wait_type(4, 5000)
        except OSError:
            self.close()
            return False
        if ack is None or len(ack) < 2:
            self.close()
            return False
        got = (ack[0] << 8) | ack[1]
        if got != self.packet_id:
            return False
        return True

    def poll(self, timeout_ms):
        if not self.connected:
            return
        self._keepalive()
        deadline = ticks_add(ticks_ms(), timeout_ms)
        while ticks_diff(deadline, ticks_ms()) > 0:
            packet = self._next_packet(ticks_diff(deadline, ticks_ms()))
            if packet is None:
                return
            ptype, flags, payload = packet
            self._dispatch(ptype, flags, payload)

    def wait_topic(self, topic, read_id, timeout_ms):
        deadline = ticks_add(ticks_ms(), timeout_ms)
        while ticks_diff(deadline, ticks_ms()) > 0:
            packet = self._next_packet(min(50, ticks_diff(deadline, ticks_ms())))
            if packet is None:
                self._keepalive()
                continue
            ptype, flags, payload = packet
            message = self._dispatch(ptype, flags, payload)
            if message and message[0] == topic and message[2] == read_id:
                return message[1]
        return None

    def close(self):
        sock = self.sock
        self.sock = None
        self.connected = False
        self.buf = b""
        if sock is None:
            return
        try:
            sock.send(b"\xe0\x00")
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _keepalive(self):
        if ticks_diff(ticks_ms(), self._last_io) < 20000:
            return
        try:
            self._send(b"\xc0\x00")
        except OSError:
            self.close()

    def _send(self, data):
        if self.sock is None:
            raise OSError("mqtt socket is closed")
        sent = 0
        while sent < len(data):
            count = self.sock.send(data[sent:])
            if not count:
                raise OSError("mqtt socket closed")
            sent += count
        self._last_io = ticks_ms()

    def _fill(self, timeout_ms):
        deadline = ticks_add(ticks_ms(), timeout_ms)
        while True:
            try:
                chunk = self.sock.recv(512)
            except OSError as err:
                if _again(err):
                    if ticks_diff(deadline, ticks_ms()) <= 0:
                        return False
                    sleep_ms(10)
                    continue
                self.close()
                raise
            if not chunk:
                self.close()
                raise OSError("broker closed the connection")
            self.buf += chunk
            self._last_io = ticks_ms()
            return True

    def _extract(self):
        buf = self.buf
        if len(buf) < 2:
            return None
        value = 0
        multiplier = 1
        index = 1
        while True:
            if index >= len(buf):
                return None
            byte = buf[index]
            value += (byte & 0x7F) * multiplier
            if multiplier > 128 * 128 * 128:
                self.close()
                raise OSError("bad mqtt length")
            index += 1
            if (byte & 0x80) == 0:
                break
            multiplier *= 128
        if value > 32768:
            self.close()
            raise OSError("mqtt packet is too large")
        total = index + value
        if len(buf) < total:
            return None
        first = buf[0]
        payload = buf[index:total]
        self.buf = buf[total:]
        return (first >> 4, first & 0x0F, payload)

    def _next_packet(self, timeout_ms):
        if not self.connected and self.sock is None:
            return None
        deadline = ticks_add(ticks_ms(), max(0, timeout_ms))
        while True:
            packet = self._extract()
            if packet is not None:
                return packet
            left = ticks_diff(deadline, ticks_ms())
            if left <= 0:
                return None
            if not self._fill(left):
                return None

    def _wait_type(self, ptype, timeout_ms):
        deadline = ticks_add(ticks_ms(), timeout_ms)
        while ticks_diff(deadline, ticks_ms()) > 0:
            packet = self._next_packet(ticks_diff(deadline, ticks_ms()))
            if packet is None:
                return None
            got, flags, payload = packet
            if got == ptype:
                return payload
            self._dispatch(got, flags, payload)
        return None

    def _dispatch(self, ptype, flags, payload):
        if ptype == 3:
            return self._on_publish(flags, payload)
        if ptype == 13:
            return None
        return None

    def _on_publish(self, flags, body):
        if len(body) < 2:
            return None
        topic_len = (body[0] << 8) | body[1]
        topic = body[2:2 + topic_len].decode()
        pos = 2 + topic_len
        qos = (flags >> 1) & 0x03
        if qos:
            if len(body) < pos + 2:
                return None
            packet_id = (body[pos] << 8) | body[pos + 1]
            pos += 2
            if qos == 1:
                self._send(bytes([0x40, 0x02, (packet_id >> 8) & 0xFF, packet_id & 0xFF]))
        data = body[pos:]
        read_id = None
        if self.on_message:
            read_id = self.on_message(topic, data)
        return (topic, data, read_id)
