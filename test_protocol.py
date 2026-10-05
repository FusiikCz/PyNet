#!/usr/bin/env python3
"""Self-test for protocol.py — framing, multiline, burst, large, compress, encrypt."""
import socket
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P

PASS = FAIL = 0
def ok(m):
    global PASS; PASS += 1; print("  [ OK ]", m)
def bad(m):
    global FAIL; FAIL += 1; print("  [FAIL]", m)

# 1) round-trip single line
a, b = socket.socketpair()
P.send_message(a, "CLIENT:connected:{\"hostname\":\"lab\"}")
r = P.receive_message(b, timeout=1)
(ok if r == "CLIENT:connected:{\"hostname\":\"lab\"}" else bad)("single-line round-trip")

# 2) multi-line payload preserved (the original bug)
a, b = socket.socketpair()
ml = "RESULT|line1\nline2\nline3\n\nnull\x00byte"
P.send_message(a, ml)
r = P.receive_message(b, timeout=1)
(ok if r == ml else bad)("multi-line/newline payload preserved (was truncated before)")

# 3) burst: two messages back-to-back, both received in order
a, b = socket.socketpair()
P.send_message(a, "MSG1")
P.send_message(a, "MSG2")
g1 = P.receive_message(b, timeout=1)
g2 = P.receive_message(b, timeout=1)
(ok if (g1, g2) == ("MSG1", "MSG2") else bad)("burst of two messages, no loss (was lost before)")

# 4) large payload (1 MiB of binary-ish data through str path)
a, b = socket.socketpair()
big = "A" * (1024 * 1024)
P.send_message(a, big, compress=True)
r = P.receive_message(b, timeout=5)
(ok if r == big else bad)("1 MiB payload survives framing+compression")

# 5) compression actually shrinks repetitive data
frame = P.build_frame("A" * 10000, compress=True)
(ok if len(frame) < 5000 else bad)("compression reduces repetitive frame size")

# 6) encryption round-trip
try:
    key = P.generate_key()
    f = P.make_fernet(key)
    a, b = socket.socketpair()
    P.send_message(a, "SECRET:top-secret-line", compress=True, fernet=f)
    raw = b.recv(65536)
    leaked = b"top-secret-line" in raw
    r = P.parse_frame(raw, fernet=f).decode()
    (ok if (r == "SECRET:top-secret-line" and not leaked) else bad)("encrypted+compressed round-trip, plaintext not on wire")
except Exception as e:
    bad("encryption test error: %s" % e)

# 7) wrong key rejected
try:
    f1 = P.make_fernet(P.generate_key()); f2 = P.make_fernet(P.generate_key())
    a, b = socket.socketpair()
    P.send_message(a, "x", compress=False, fernet=f1)
    raw = b.recv(65536)
    try:
        P.parse_frame(raw, fernet=f2)
        bad("wrong key should have been rejected")
    except P.ProtocolError:
        ok("wrong encryption key rejected")
except Exception as e:
    bad("wrong-key test error: %s" % e)

# 8) oversize declared length rejected
try:
    import struct
    bad_frame = struct.pack("!2sBI", b"PN", 0, P.MAX_FRAME + 1)
    try:
        P.parse_frame(bad_frame)
        bad("oversize frame should be rejected")
    except P.ProtocolError:
        ok("oversize frame rejected (DoS guard)")
except Exception as e:
    bad("oversize test error: %s" % e)

# 9) bad magic rejected
try:
    P.parse_frame(b"XX\x00\x00\x00\x00\x00")
    bad("bad magic should be rejected")
except P.ProtocolError:
    ok("bad magic rejected")

# 10) timeout returns None
a, b = socket.socketpair()
r = P.receive_message(b, timeout=0.2)
(ok if r is None else bad)("timeout returns None")

print("\n===================== SUMMARY =====================")
print("  PASS=%d  FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
