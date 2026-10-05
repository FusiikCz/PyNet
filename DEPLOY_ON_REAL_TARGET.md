# PyNet — Deployment Guide (Theoretical, Lab-Only)

> **Legal Disclaimer** — This document is for educational purposes and authorized security testing only.
> Unauthorized access to computer systems is illegal. Run PyNet only against machines you own or are
> explicitly permitted to test (your own lab, a bug-bounty scope, or a signed engagement). The authors
> assume no liability for misuse.

---

## 1. What this guide covers

This is a **theoretical** deployment guide for PyNet on a real target. It does not name a specific
target and avoids target-specific details. It covers:

- Pre-deployment checklist (network, accounts, prerequisites)
- Server deployment (listening, auth, firewall, dashboard)
- Client deployment (config, delivery, persistence options)
- Wire protocol notes (framing, compression, optional encryption)
- Operational workflow (connect → register → command → monitor)
- Troubleshooting
- Cleanup and evidence handling

All steps assume a lab or authorized environment.

---

## 2. Pre-deployment checklist

### 2.1 Network
- Confirm the server can reach the target(s) on the configured port (default **12345**).
- Ensure return traffic is allowed (firewall rules, NAT, routing).
- If you need to cross a firewall, consider a tunnel (SSH reverse tunnel, HTTP CONNECT proxy) or
  deploy the server inside the target network.

### 2.2 Accounts & privileges
- Client needs sufficient privileges for the commands you plan to run (e.g., service control, registry,
  network scans).
- For MITM, you typically need root/admin on the attacker machine and the ability to inject ARP/DNS
  packets on the chosen interface.

### 2.3 Prerequisites
- Python 3.7+ on server and client.
- Core dependencies: `scapy>=2.5.0`, `flask>=2.3.0`, `cryptography>=41.0.0`.
- Optional dependencies for full features: `psutil`, `Pillow`, `pyperclip`, `pynput`,
  `opencv-python`, `pyaudio`, `netifaces` (Windows needs VC++ build tools).

### 2.4 Configuration files
- `server_config.json` — set `host`, `port`, `enable_authentication`, `monitoring_port`.
- `client_config.json` — set `server_host`, `server_port`, `compression_enabled`, `encryption_enabled`,
  `encryption_key` (if using encryption).
- For encryption: generate a Fernet key once (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) and distribute it out-of-band.

---

## 3. Server deployment

### 3.1 Start the server
```bash
python server.py
```
- Listens on the configured port (default 12345).
- Starts the web monitoring dashboard at `http://localhost:8080` (default).
- Creates config/log/metrics files on first run.

### 3.2 Authentication
- Set `enable_authentication: true` in `server_config.json`.
- The server auto-generates an `auth_token` if it is null.
- Distribute the token to clients (e.g., embed in `client_config.json` or pass via environment).

### 3.3 Firewall & exposure
- If exposing the server externally, restrict the port to known IPs.
- Prefer a tunnel (SSH, WireGuard, Tailscale) over direct exposure.
- The dashboard is plain HTTP by default; place it behind a reverse proxy with TLS if needed.

### 3.4 Rate limiting & metrics
- `rate_limit_enabled`, `rate_limit_requests` control command rate per client.
- `enable_metrics` writes `server_metrics.json` with uptime, connections, bytes sent/received.

---

## 4. Client deployment

### 4.1 Configure the client
Edit `client_config.json`:
```json
{
    "server_host": "<server IP or FQDN>",
    "server_port": 12345,
    "reconnect_interval": 30,
    "keepalive_interval": 60,
    "compression_enabled": true,
    "encryption_enabled": false,
    "encryption_key": null,
    "stealth_mode": false,
    "keylogging_enabled": false
}
```
**Important:** Set `server_host` to the server's reachable address.

### 4.2 Delivery options (choose based on your environment)
- Copy the files manually and run `python client.py`.
- Use a script/wrapper to drop files and start the client.
- For Windows: compile to `.exe` (e.g., PyInstaller) and deploy via RDP, shared folder, or scheduled task.

### 4.3 Persistence (examples)
- **Windows:** Scheduled Task, Run key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
- **Linux:** systemd user service, cron, or `~/.bashrc` entry (with care).
- **macOS:** launch agent (`~/Library/LaunchAgents`).

### 4.4 Stealth considerations
- `stealth_mode: true` attempts to hide the process (platform-dependent).
- `anti_debugging: true` adds basic anti-debug checks.
- Rename `client.py`/`client.exe` to something generic.
- Use compression (default on) to reduce wire size.

---

## 5. Wire protocol notes

This upgraded build uses a **length-prefixed framing layer** (`protocol.py`).

**Frame layout:**
```
+--------+--------+------------------+-------------------+
| MAGIC  | FLAGS  |  LENGTH (uint32) |      PAYLOAD      |
| 2 bytes| 1 byte |   4 bytes, BE    |  LENGTH bytes     |
+--------+--------+------------------+-------------------+
   "PN"     0x01 = zlib-compressed
            0x02 = Fernet-encrypted
```
- Binary-safe: payloads may contain newlines, nulls, UTF-8, or arbitrary bytes.
- Compression is applied only when it shrinks the payload.
- Encryption (Fernet) is applied **after** compression; both peers must share the key.
- `MAX_FRAME = 64 MiB` hard cap prevents memory-exhaustion DoS.
- Malformed frames raise `ProtocolError` and the connection is dropped.

**Backward compatibility:**
- Old configs work without migration; missing keys default safely.
- The server and client must both use the upgraded files (framing changed).

---

## 6. Operational workflow

### 6.1 Start the server
```bash
python server.py
```
- Confirm the dashboard is reachable at `http://<server>:8080`.
- Type `help` (`h`) in the console to see all commands.

### 6.2 Start a client
```bash
python client.py
```
- The client connects, registers with `CLIENT:connected:{json}`, and sends keepalives.
- Check `status` on the server to see connected clients.

### 6.3 Commands
- `7` — list connected clients
- `8` — send a command to a specific client (by number)
- `1` — send a manual command to all clients
- `3` — request system info from all clients
- `status` — server status and client count
- `history` — command history
- `config` — show/edit server configuration

See the README for the full command reference (75+ commands).

### 6.4 Monitoring
- Web dashboard shows connected clients, basic metrics, and health.
- `server_metrics.json` logs uptime, peak clients, bytes sent/received, error count.

---

## 7. Troubleshooting

**Client does not appear in the server list**
- Confirm `server_host` / `server_port` in `client_config.json` match the server.
- Ensure the server is running and the port is reachable (firewall/NAT).
- The registration parse bug from older builds is fixed here — update **both** `server.py` and
  `client.py` together.

**Messages look corrupted or truncated**
- You are mixing old and new files. The upgraded build requires the new `protocol.py` and the
  matching `server.py` / `client.py`. Copy **all** files from this bundle.

**Compression/encryption mismatches**
- If `encryption_enabled: true`, both sides must share the same Fernet key.
- If compression is on (default), the server will decompress automatically when the flag is set.

**Large payloads fail**
- The hard cap is 64 MiB per frame. Split very large files into chunks or use the file transfer
  commands (`9`–`12`) which handle base64 encoding in the normal message path.

**MITM captures nothing**
- Run as root/admin, verify the interface, target and gateway IPs.
- Confirm ARP spoofing is enabled (you did not pass `--no-arp`).

---

## 8. Cleanup and evidence handling

### 8.1 Server
- Stop the server (`end` in the console).
- Archive or remove `server.log`, `command_history.json`, `server_metrics.json`, `server_config.json`.

### 8.2 Client
- Stop the client (Ctrl+C or terminate the process).
- Remove `client_config.json`, `client.log`.
- Remove persistence mechanisms (scheduled tasks, registry keys, systemd units).

### 8.3 Network artifacts
- If you used ARP spoofing, run `arp -d <target>` on affected machines to clear ARP cache entries.
- Clear DNS cache if you used DNS spoofing.

---

## 9. Security considerations

1. **Authentication** — enable token auth and keep the token secret.
2. **Encryption** — enable Fernet when traffic crosses an untrusted network.
3. **Transport** — prefer a tunnel (SSH, WireGuard) over direct exposure.
4. **Firewall** — restrict who can reach the server port and dashboard.
5. **Logging** — review logs for unexpected activity.
6. **Authorization** — only against systems you own or are explicitly permitted to test.

> Note: dashboards and the wire protocol are plain HTTP/unencrypted by default. Treat this as a lab
> tool, not hardened production software.

---

## 10. File transfer note

The original `send_file_data` / `receive_file_data` functions in `client.py` are dead code. The live
path sends `FILE_DATA:{base64}` inline as a normal framed message. Large file transfers therefore
ride the normal message path and are subject to the 64 MiB frame cap.

---

## Appendix A — Quick commands

```bash
# Server
python server.py

# Client (after editing client_config.json)
python client.py

# MITM (example)
python mitm.py --list-interfaces
python mitm.py -i eth0 -t 192.168.1.100 -g 192.168.1.1
```

---

## Appendix B — Generating a Fernet key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Save the output string and set it in `encryption_key` on both server and client configs, then set
`encryption_enabled: true`.

---

*End of guide.*
