#!/usr/bin/env python3
"""
protocol.py — Robust message framing for the PyNet server/client/MITM suite.

Replaces the fragile newline-delimited protocol used by server.py / client.py.

WHY (defects this fixes, all reproduced against the original code):
  1) The client compressed (and optionally encrypted) outgoing messages by
     default, but the server never decompressed/decrypted them, so the server
     could not parse client messages at all with the default config
     (compression_enabled=True).
  2) The newline delimiter truncated any message containing "\\n" (command
     output, keylogs, file contents, browser history).
  3) Bytes after the first "\\n" were discarded, so two messages arriving in a
     single TCP segment lost the second one.
  4) The server used sock.send() instead of sendall().

DESIGN
  - Length-prefixed framing: 7-byte header = MAGIC(2) | FLAGS(1) | LEN(4, uint32 BE).
  - Binary-safe: payload may contain any bytes, including newlines/nulls.
  - Optional per-message compression (zlib, stdlib).
  - Optional authenticated encryption (Fernet, AES-128-CBC + HMAC). Encryption is
    applied AFTER compression; both peers must share the Fernet key out-of-band.
  - Strict size cap to prevent a malicious peer from forcing huge allocations.

LAB / AUTHORIZED-TESTING USE ONLY. See the project README and DISCLAIMER.
"""

import struct
import zlib
import socket

MAGIC = b"PN"                     # protocol magic
HEADER = struct.Struct("!2sBI")   # magic, flags, payload length
HEADER_SIZE = HEADER.size         # 7 bytes
MAX_FRAME = 64 * 1024 * 1024      # 64 MiB hard cap (prevents memory-exhaustion DoS)

FLAG_COMPRESSED = 0x01
FLAG_ENCRYPTED = 0x02
FLAG_MASK = FLAG_COMPRESSED | FLAG_ENCRYPTED


class ProtocolError(Exception):
    """Raised on malformed frames, oversize frames, or crypto failures."""


def _as_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError("payload must be str or bytes")


def build_frame(payload, compress=False, fernet=None):
    """Encode a payload (str|bytes) into a single framed message (bytes)."""
    body = _as_bytes(payload)
    flags = 0

    if compress:
        compressed = zlib.compress(body, 6)
        # Only keep compression if it actually helps.
        if len(compressed) < len(body):
            body = compressed
            flags |= FLAG_COMPRESSED

    if fernet is not None:
        body = fernet.encrypt(body)
        flags |= FLAG_ENCRYPTED

    if len(body) > MAX_FRAME:
        raise ProtocolError("frame exceeds MAX_FRAME ({})".format(MAX_FRAME))

    return HEADER.pack(MAGIC, flags, len(body)) + body


def parse_frame(frame, fernet=None):
    """Decode a complete framed message (bytes) back into payload bytes."""
    if len(frame) < HEADER_SIZE:
        raise ProtocolError("frame shorter than header")
    magic, flags, length = HEADER.unpack(frame[:HEADER_SIZE])
    if magic != MAGIC:
        raise ProtocolError("bad magic (not a PyNet frame)")
    if length > MAX_FRAME:
        raise ProtocolError("declared length {} exceeds MAX_FRAME".format(length))
    body = frame[HEADER_SIZE:HEADER_SIZE + length]
    if len(body) != length:
        raise ProtocolError("truncated frame: got {} of {} bytes".format(len(body), length))

    if flags & FLAG_ENCRYPTED:
        if fernet is None:
            raise ProtocolError("frame is encrypted but no Fernet key was provided")
        try:
            body = fernet.decrypt(body)
        except Exception as exc:  # InvalidToken, etc.
            raise ProtocolError("decryption failed: {}".format(exc))
    if flags & FLAG_COMPRESSED:
        try:
            body = zlib.decompress(body)
        except zlib.error as exc:
            raise ProtocolError("decompression failed: {}".format(exc))
    return body


def _sendall(sock, data):
    """Send all bytes, compatible with socket and socket-like objects."""
    if hasattr(sock, "sendall"):
        sock.sendall(data)
    else:
        view = memoryview(data)
        total = 0
        while total < len(data):
            sent = sock.send(view[total:])
            if sent == 0:
                raise ConnectionResetError("socket closed during send")
            total += sent


def _recv_exact(sock, n):
    """Read exactly n bytes or raise ConnectionResetError."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionResetError("socket closed during recv")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_message(sock, message, compress=True, fernet=None):
    """Send one framed message. Returns True on success, False on error."""
    frame = build_frame(message, compress=compress, fernet=fernet)
    _sendall(sock, frame)
    return True


def receive_message(sock, timeout=None, fernet=None, raise_on_timeout=False):
    """
    Receive exactly one framed message.

    Returns decoded str, or None on timeout / clean close.
    Raises ProtocolError on malformed frames.
    If raise_on_timeout is True, a timeout propagates as socket.timeout instead
    of returning None (used by the client to preserve its keepalive path).
    """
    old_timeout = None
    if timeout is not None:
        try:
            old_timeout = sock.gettimeout()
            sock.settimeout(timeout)
        except (OSError, AttributeError):
            old_timeout = None
    try:
        try:
            header = _recv_exact(sock, HEADER_SIZE)
        except socket.timeout:
            if raise_on_timeout:
                raise
            return None
        except ConnectionResetError:
            return None
        magic, flags, length = HEADER.unpack(header)
        if magic != MAGIC:
            raise ProtocolError("bad magic (not a PyNet frame)")
        if length > MAX_FRAME:
            raise ProtocolError("declared length {} exceeds MAX_FRAME".format(length))
        body = _recv_exact(sock, length) if length else b""
        frame = header + body
        payload = parse_frame(frame, fernet=fernet)
        return payload.decode("utf-8", errors="replace")
    finally:
        if timeout is not None and old_timeout is not None:
            try:
                sock.settimeout(old_timeout)
            except OSError:
                pass


def make_fernet(key):
    """Build a Fernet instance from a key string/bytes. Returns None if unavailable."""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def generate_key():
    """Generate a new Fernet key (str)."""
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()
