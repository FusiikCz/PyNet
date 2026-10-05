#!/usr/bin/env python3
"""
e2e_test.py — End-to-end verification of the framing upgrade against the
patched PyNet server, using the patched protocol on the client side.

Proves:
  A) the exact original defect is fixed: client.send_message output is parsed
     by server.receive_message (default compression on),
  B) the real server accept/handle_client loop registers a framed client,
  C) server -> client direction works with a multi-line payload,
  D) two messages in one burst are both delivered (no loss),
  E) a multi-line health payload survives client -> server intact.
"""
import sys
import socket
import json
import time
import threading

REPO = sys.argv[1] if len(sys.argv) > 1 else "/home/user/pynet_fixed"
sys.path.insert(0, REPO)

import protocol as P
import server as S

PASS = FAIL = 0
def ok(m):
    global PASS; PASS += 1; print("  [ OK ]", m)
def bad(m):
    global FAIL; FAIL += 1; print("  [FAIL]", m)

# ---------------------------------------------------------------- A) module-level
print("[A] module-level: client frame parsed by server")
import client as C
C.config = dict(C.DEFAULT_CONFIG)
c1, s1 = socket.socketpair()
msg = 'CLIENT:connected:' + json.dumps({'hostname': 'lab', 'platform': 'Linux', 'client_name': 'lab'})
C.send_message(c1, msg)
got = S.receive_message(s1, timeout=1)
(ok if got == msg else bad)("client.send_message -> server.receive_message (default compression ON)")
c1.close(); s1.close()

# ---------------------------------------------------------------- server process
print("[B] real server loop: framed client registration")
S.setup_logging('ERROR')
S.config = dict(S.DEFAULT_CONFIG)
S.config.update({
    'host': '127.0.0.1', 'port': 12399, 'socket_timeout': 5.0,
    'enable_monitoring': False, 'enable_backup': False, 'client_timeout': 300,
})
S.is_running = True
th = threading.Thread(target=S.server_program, daemon=True)
th.start()

# wait for listener
for _ in range(40):
    try:
        probe = socket.create_connection(('127.0.0.1', 12399), timeout=0.5)
        probe.close()
        break
    except OSError:
        time.sleep(0.1)

cli = socket.create_connection(('127.0.0.1', 12399), timeout=5)
P.send_message(cli, 'CLIENT:connected:' + json.dumps(
    {'hostname': 'lab-e2e', 'platform': 'Linux', 'client_name': 'lab-e2e'}))

# poll for registration
registered = False
for _ in range(30):
    with S.clients_lock:
        infos = list(S.clients_info.values())
    if any(i.get('hostname') == 'lab-e2e' for i in infos):
        registered = True
        break
    time.sleep(0.1)
(ok if registered else bad)("server registered the framed client (hostname=lab-e2e)")

# ---------------------------------------------------------------- C) server -> client
print("[C] server -> client: multi-line payload")
ml = 'execute:echo hello' + '\n' + 'second line of output'
S.send_message_to_all_clients(ml)
got = P.receive_message(cli, timeout=3)
(ok if got == ml else bad)("server -> client multi-line payload intact")

# ---------------------------------------------------------------- D) burst
print("[D] burst: two server messages, both delivered")
S.send_message_to_all_clients('ping')
S.send_message_to_all_clients('get_system_info')
g1 = P.receive_message(cli, timeout=3)
g2 = P.receive_message(cli, timeout=3)
(ok if (g1, g2) == ('ping', 'get_system_info') else bad)("burst delivered in order: %r, %r" % (g1, g2))

# ---------------------------------------------------------------- E) multiline c->s
print("[E] client -> server: multi-line health payload preserved")
mlh = 'CLIENT:health:' + json.dumps({'status': 'ok', 'note': 'line1\nline2'})
P.send_message(cli, mlh)

health_ok = False
for _ in range(30):
    with S.clients_lock:
        for i in S.clients_info.values():
            h = i.get('last_health')
            if h and h.get('note') == 'line1\nline2':
                health_ok = True
    if health_ok:
        break
    time.sleep(0.1)
(ok if health_ok else bad)("client -> server multi-line payload preserved")

cli.close()
S.is_running = False
time.sleep(0.3)

print("\n===================== SUMMARY =====================")
print("  PASS=%d  FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
