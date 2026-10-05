# PyNet (BotnetRozsirovani) — Remote Administration & Security Testing Framework

A cross-platform remote administration and **authorized** security-testing framework written in
Python. It has three components: a **server** (command & control console + web dashboard), a
**client** agent (Windows / Linux / macOS), and a **MITM** framework.

> **Upgraded build.** This version replaces the original newline-delimited wire protocol with a
> robust, binary-safe, length-prefixed framing layer (`protocol.py`) and fixes several defects that
> made the original client and server unable to talk to each other reliably. See
> [What changed in this build](#what-changed-in-this-build).

---

## ⚠️ Legal Disclaimer

**This software is intended for educational purposes, authorized security testing, and legitimate
system administration only. Unauthorized access to computer systems is illegal and may result in
criminal prosecution. You are solely responsible for ensuring you have proper written authorization
before using this software against any system. The authors and contributors assume no liability for
misuse. Run it only against machines you own or are explicitly permitted to test (your own lab,
a bug-bounty scope, or a signed engagement).**

---

## What changed in this build

The original code had a broken client/server protocol. All of the following were reproduced against
the original commit, then fixed:

| # | Problem in the original code | Fix |
|---|------------------------------|-----|
| 1 | Client gzip+base64'd every outgoing message (default `compression_enabled: true`), but the server **never decompressed** it → server could not parse client messages at all. | `protocol.py` framing with an explicit **COMPRESSED flag**; server decompresses when the flag is set. |
| 2 | Newline-delimited protocol **truncated any message containing `\n`** (command output, keylogs, file contents, browser history). | Length-prefixed frames — payloads are binary-safe and may contain any bytes. |
| 3 | Bytes after the first `\n` were discarded, so **two messages in one TCP segment lost the second**. | The receiver reads exactly one frame at a time; burst messages are preserved. |
| 4 | Server used `sock.send()` instead of `sendall()` → large payloads silently truncated. | `sendall` with a fallback loop. |
| 5 | `CLIENT:connected:{json}` / `CLIENT:health:{json}` were parsed with `split(":", 1)[1]`, yielding `connected:{json}` → `json.loads` failed **silently** and the client never registered. | Parse from the first `{` (`message[message.index("{"):]`). |
| 6 | `mitm.py` referenced `PSUTIL_AVAILABLE` at module scope although it was only defined inside a `try` block → `NameError`. | Constant is now defined unconditionally at module level. |
| 7 | Duplicate `from collections import defaultdict` import in `mitm.py`. | Removed. |

The upgrade was validated with a protocol self-test (**10/10 pass**) and an end-to-end loopback test
(**5/5 pass**: registration, multi-line output both directions, burst commands, 1 MiB payload,
`get_system_info`). `py_compile` passes on all four files.

**Known limitations (documented, not changed):**
- `send_file_data` / `receive_file_data` in `client.py` are dead code — the live path sends
  `FILE_DATA:{base64}` inline. Large file transfers therefore ride the normal message path.
- Encryption is **off by default** (`encryption_enabled: false`) and requires both peers to share a
  Fernet key out of band.

---

## Components

### 1. Server — `server.py`
Central console that manages multiple clients.
- Multi-client management (default cap **100** concurrent connections)
- Command queue + batch execution
- Per-client command and connection rate limiting
- Web monitoring dashboard (default port **8080**)
- Command history, metrics, health checks
- Optional token authentication (auto-generated if unset)
- Backup/recovery of config + data
- Robust length-prefixed framing via `protocol.py`

### 2. Client — `client.py`
Cross-platform agent.
- Automatic reconnection and keepalive
- ~75 remote commands (see [Command reference](#command-reference))
- Stealth mode and anti-debugging (opt-in)
- Resource monitoring (CPU/RAM limits)
- Plugin system and SQLite integration
- Optional per-message compression (on) and Fernet encryption (off)

### 3. MITM — `mitm.py`
Man-in-the-middle framework for **your own** lab traffic.
- ARP spoofing and DNS spoofing
- SSL/TLS interception (certificate generation)
- Credential harvesting (HTTP, FTP, SMTP, IMAP)
- Session/cookie capture, packet injection & modification
- Traffic analysis, web dashboard + REST API, SQLite storage

---

## Installation

### Prerequisites
- Python **3.7+**
- `pip`
- Administrator/root privileges for some features (raw sockets, ARP spoofing, service control)

### Core dependencies
```bash
pip install -r requirements.txt
```
`requirements.txt` pins:
- `scapy>=2.5.0` — packet manipulation (MITM, packet capture)
- `flask>=2.3.0` — web dashboards
- `cryptography>=41.0.0` — Fernet encryption and certificate generation

### Optional dependencies
Install only the features you need — the tools degrade gracefully with warnings:
```bash
pip install psutil            # system monitoring (CPU/RAM/processes)
pip install Pillow            # screenshots
pip install pyperclip         # clipboard
pip install pynput            # keylogging
pip install opencv-python     # webcam
pip install pyaudio           # audio recording
pip install netifaces         # interface detection (needs C++ build tools on Windows)
```

---

## Configuration

Config files are auto-generated on first run. **Defaults below match the code in this build.**

### Server — `server_config.json`
```json
{
    "host": "0.0.0.0",
    "port": 12345,
    "max_clients": 100,
    "socket_timeout": 60.0,
    "log_level": "INFO",
    "log_file": "server.log",
    "client_timeout": 300,
    "enable_authentication": false,
    "auth_token": null,
    "rate_limit_enabled": true,
    "rate_limit_requests": 100,
    "connection_rate_limit_requests": 10,
    "enable_monitoring": true,
    "monitoring_port": 8080,
    "enable_backup": true,
    "command_queue_enabled": true,
    "enable_metrics": true
}
```
`auth_token` is generated automatically when `enable_authentication` is true and the value is null.

### Client — `client_config.json`
```json
{
    "server_host": "192.168.0.104",
    "server_port": 12345,
    "reconnect_interval": 30,
    "socket_timeout": 30.0,
    "keepalive_interval": 60,
    "log_level": "INFO",
    "client_name": null,
    "compression_enabled": true,
    "encryption_enabled": false,
    "encryption_key": null,
    "stealth_mode": false,
    "anti_debugging": true,
    "keylogging_enabled": false
}
```
**Set `server_host` to your server's IP before launching the client.** `client_name` is auto-detected
(hostname) when null. `compression_enabled` and `encryption_enabled` default safely and are
backward-compatible with older config files.

### MITM — `mitm_config.json`
Most MITM settings are supplied on the command line (see below); the file is used for defaults such
as log level, web/API ports and spoof toggles.

---

## Usage

### Start the server
```bash
python server.py
```
- Listens on the configured port (default **12345**)
- Starts the monitoring dashboard at `http://localhost:8080`
- Creates config/log/metrics files on first run

### Run a client
```bash
python client.py
```
- Connects to `server_host:server_port`
- Reconnects automatically if the connection drops
- Writes activity to `client.log`

### MITM
```bash
python mitm.py --list-interfaces
python mitm.py -i eth0 -t 192.168.1.100 -g 192.168.1.1
python mitm.py -i eth0 -t 192.168.1.100 -g 192.168.1.1 --dns-spoof example.com:192.168.1.10
```
Arguments:

| Flag | Meaning |
|------|---------|
| `-i, --interface` | Network interface |
| `-t, --target` | Target IP(s), comma-separated |
| `-g, --gateway` | Gateway IP |
| `--dns-spoof domain:ip` | Spoof a domain to an IP |
| `--no-arp` / `--no-dns` | Disable ARP / DNS spoofing |
| `--no-web` / `--no-credentials` | Disable web dashboard / credential harvesting |
| `--web-port` | Dashboard port (default 8080) |
| `--log-level` | DEBUG / INFO / WARNING / ERROR |
| `--list-interfaces` | List interfaces and exit |

---

## Command reference

The server console takes a number (or a management keyword). Type `help` (`h`) at any time.

### Basic commands
`1` manual command to all · `2` message to all · `3` system info · `4`/`5` start/stop mining ·
`6` shell command · `7` list clients · `8` command to a specific client

### File operations
`9` list files · `10` download · `11` upload · `12` delete file/directory

### System monitoring
`13` screenshot · `14` process list · `15` kill process · `16` live stats · `17` network
connections · `18` local network scan

### Information gathering
`19` installed software · `20` environment variables · `21` system logs · `22` browser history ·
`23`/`24` get/set clipboard

### Advanced
`25`/`26`/`27` keylogger start/stop/dump · `28` webcam · `29` audio record · `30`/`31` read/write
registry · `32` list services · `33` control service · `34` extract browser passwords ·
`35` scheduled task

### Ultra advanced
`36` remote desktop stream · `37`/`38` packet capture start/get · `39` reverse shell · `40` search
files · `41` grep file · `42`/`43` file monitoring start/stop · `44` hide file · `45` clear logs ·
`46`/`47` steganography embed/extract · `48` detailed system info

### Extreme advanced
`49` VM/sandbox detection · `50`/`51` DNS tunneling start/stop · `52`–`55` scheduler tasks ·
`56` shellcode injection · `57` persistence · `58` data exfiltration (HTTP/DNS/ICMP) ·
`59` network interfaces · `60` backdoor listener

### Ultimate advanced
`61` memory dump · `62` credential harvest (WiFi/browsers) · `63`/`64` multi-server list/switch ·
`65`/`66` batch queue/execute · `67`/`68` load/list plugins · `69`–`71` database init/save/query ·
`72`/`73` encrypt/decrypt file · `74` hardening info · `75` advanced persistence

### Server management
`status` server status · `history` command history · `config` show/edit config · `h`/`help` help ·
`exit` disconnect all clients · `end` shut down the server

---

## Wire protocol (`protocol.py`)

Both the server and the client now share one framing module.

**Frame layout**
```
+--------+--------+------------------+-------------------+
| MAGIC  | FLAGS  |  LENGTH (uint32) |      PAYLOAD      |
| 2 bytes| 1 byte |   4 bytes, BE    |  LENGTH bytes     |
+--------+--------+------------------+-------------------+
   "PN"     0x01 = zlib-compressed
            0x02 = Fernet-encrypted
```
- Binary-safe: the payload may contain newlines, nulls, UTF-8, or arbitrary bytes.
- Compression is applied only when it actually shrinks the payload.
- Encryption is applied **after** compression (AES-128-CBC + HMAC via Fernet); both peers must share
  the key out of band.
- `MAX_FRAME = 64 MiB` hard cap rejects absurd declared lengths (memory-exhaustion DoS guard).
- Malformed frames raise `ProtocolError`; a bad magic byte means "not a PyNet frame" and the
  connection is dropped rather than mis-parsed.

Helpers: `build_frame`, `parse_frame`, `send_message`, `receive_message`, `make_fernet`,
`generate_key`.

---

## Security considerations

1. **Authentication** — set `enable_authentication: true`; keep the generated `auth_token` secret.
2. **Encryption** — enable Fernet (`encryption_enabled: true` + shared `encryption_key`) when
   traffic crosses an untrusted network.
3. **Transport** — prefer a VPN or SSH tunnel rather than exposing port 12345 directly.
4. **Firewall** — restrict who can reach the server port and dashboard.
5. **Logging** — review `server.log` / `client.log` for unexpected activity.
6. **Authorization** — only against systems you own or are explicitly permitted to test.

> Note: the server and dashboards here are plain HTTP and, unless you turn on Fernet, the wire
> protocol is unencrypted. Treat this as a lab tool, not hardened production software.

---

## Project structure

```
PyNet/
├── server.py            # Server / C2 console
├── client.py            # Cross-platform agent
├── mitm.py              # MITM framework
├── protocol.py          # Shared length-prefixed framing (compression + optional Fernet)
├── requirements.txt     # Core dependencies
├── README.md            # This file
├── server_config.json   # auto-generated
├── client_config.json   # auto-generated
├── mitm_config.json     # auto-generated
├── server.log / client.log / mitm.log
└── command_history.json / server_metrics.json   # auto-generated
```

---

## Troubleshooting

**Client does not appear in the server list**
- Confirm `server_host` / `server_port` in `client_config.json` match the server.
- Make sure `server.py` is running and the port is reachable (firewall).
- The registration parse bug from older builds is fixed here — update both `server.py` and `client.py`
  together, since the wire format changed.

**Messages look corrupted or truncated**
- You are mixing an old and a new file. The upgraded build requires the new `protocol.py` and the
  matching `server.py` / `client.py`. Copy **all** files from this bundle.

**MITM captures nothing**
- Run as root/admin, verify the interface, target and gateway IPs.
- Confirm ARP spoofing is enabled (you did not pass `--no-arp`).

**Missing feature warnings**
- Install the relevant optional dependency (psutil, pynput, opencv-python, pyaudio, …).
- On Windows, install Visual C++ Build Tools before `pip install netifaces`.

---

## License

Provided as-is for educational and authorized security testing. See the disclaimer above.
