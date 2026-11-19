import binascii
import hashlib
import os


def _xor(mask, key):
    out = bytearray(len(key))
    for index, byte in enumerate(key):
        out[index] = byte ^ mask
    return bytes(out)


def hmac_sha256(key, message):
    if isinstance(key, str):
        key = key.encode()
    if isinstance(message, str):
        message = message.encode()
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    if len(key) < 64:
        key = key + (b"\x00" * (64 - len(key)))
    inner = hashlib.sha256(_xor(0x36, key) + message).digest()
    return hashlib.sha256(_xor(0x5C, key) + inner).digest()


def hex_lower(data):
    text = binascii.hexlify(data)
    if isinstance(text, str):
        return text
    return text.decode()


def decode_key(hex_key):
    text = str(hex_key).strip().lower()
    if len(text) != 64:
        raise ValueError("key must be 64 hex characters")
    for char in text:
        if char not in "0123456789abcdef":
            raise ValueError("key must be 64 hex characters")
    return binascii.unhexlify(text)


def hmac_hex(key_hex, text):
    return hex_lower(hmac_sha256(decode_key(key_hex), text.encode()))


def random_id():
    return hex_lower(os.urandom(16))
