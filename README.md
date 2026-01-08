# BotnetRozsirovani - Remote Administration & Security Testing Framework

A comprehensive cross-platform remote administration and security testing framework written in Python. This project consists of three main components: a server for managing multiple clients, a client agent, and a Man-in-the-Middle (MITM) attack framework.

##  Legal Disclaimer

**This software is intended for educational purposes, authorized security testing, and legitimate system administration only. Unauthorized access to computer systems is illegal and may result in criminal prosecution. Users are solely responsible for ensuring they have proper authorization before using this software. The authors and contributors assume no liability for misuse of this software.
But i cant really stop you....**

##  Components

### 1. Server (`server.py`)
A centralized command and control server that manages multiple client connections. Features include:
- Multi-client management (up to 100 concurrent connections)
- Command queue system
- Rate limiting and connection management
- Web-based monitoring dashboard (port 8080)
- Command history tracking
- Metrics and statistics collection
- Authentication support
- Backup and recovery mechanisms

### 2. Client (`client.py`)
A cross-platform client agent that connects to the server and executes commands. Supports Windows, Linux, and macOS with:
- Automatic reconnection
- Stealth mode capabilities
- Anti-debugging features
- Resource monitoring
- Plugin system
- Database integration
- Encryption support

### 3. MITM Framework (`mitm.py`)
An advanced Man-in-the-Middle attack framework for security testing:
- ARP Spoofing
- DNS Spoofing
- SSL/TLS Interception
- Credential Harvesting (HTTP, FTP, SMTP, IMAP)
- Session Hijacking
- Packet Injection & Modification
- Web Dashboard & REST API
- Traffic Analysis
- Database Storage

##  Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager
- Administrator/root privileges (for some features)

### Required Dependencies

Install the core dependencies:

```bash
pip install -r requirements.txt
```

The `requirements.txt` includes:
- `scapy>=2.5.0` - Network packet manipulation
- `flask>=2.3.0` - Web dashboard
- `cryptography>=41.0.0` - Encryption and certificate generation

### Optional Dependencies

For full functionality, install additional optional packages:

```bash
# System monitoring
pip install psutil

# Screenshot capabilities
pip install Pillow
# OR
pip install pyscreenshot

# Clipboard access
pip install pyperclip

# Keylogging
pip install pynput

# Webcam access
pip install opencv-python

# Audio recording
pip install pyaudio wave

# Network interface detection (Windows requires Visual C++ Build Tools)
pip install netifaces
```

**Note for Windows users:** To install `netifaces` on Windows, you need Visual C++ Build Tools:
1. Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Install the C++ build tools
3. Run: `pip install netifaces`

##  Configuration

### Server Configuration

The server creates a `server_config.json` file on first run with default settings:

```json
{
    "host": "0.0.0.0",
    "port": 12345,
    "max_clients": 100,
    "socket_timeout": 60.0,
    "log_level": "INFO",
    "log_file": "server.log",
    "enable_authentication": false,
    "rate_limit_enabled": true,
    "enable_monitoring": true,
    "monitoring_port": 8080
}
```

Edit `server_config.json` to customize server settings.

### Client Configuration

The client creates a `client_config.json` file on first run:

```json
{
    "server_host": "192.168.0.104",
    "server_port": 12345,
    "reconnect_interval": 30,
    "log_level": "INFO",
    "stealth_mode": false,
    "encryption_enabled": false
}
```

**Important:** Update `server_host` with your server's IP address before running the client.

### MITM Configuration

The MITM framework creates a `mitm_config.json` file:

```json
{
    "log_level": "INFO",
    "web_port": 8080,
    "api_port": 8081,
    "enable_arp_spoof": true,
    "enable_dns_spoof": true,
    "enable_ssl_intercept": true,
    "target_ips": [],
    "gateway_ip": null,
    "interface": null
}
```

## 📖 Usage

### Starting the Server

```bash
python server.py
```

The server will:
- Start listening on the configured port (default: 12345)
- Create configuration files if they don't exist
- Start the web monitoring dashboard (default: http://localhost:8080)
- Display connection status and client count

**Server Commands:**
- Type `h` or `help` to see all available commands
- Type `status` to view server statistics
- Type `7` to list connected clients
- Type `end` to shutdown the server

### Running the Client

```bash
python client.py
```

The client will:
- Connect to the configured server
- Automatically reconnect if connection is lost
- Execute commands received from the server
- Log activities to `client.log`

**Note:** Ensure the server is running and the client configuration has the correct server IP address.

### Using the MITM Framework

```bash
python mitm.py --help
```

Common usage:

```bash
# Basic MITM attack
python mitm.py --target 192.168.1.100 --gateway 192.168.1.1 --interface eth0

# With DNS spoofing
python mitm.py --target 192.168.1.100 --gateway 192.168.1.1 --interface eth0 --dns-spoof

# Enable web dashboard
python mitm.py --target 192.168.1.100 --gateway 192.168.1.1 --interface eth0 --web-dashboard
```

Access the web dashboard at `http://localhost:8080` (default port).

##  Key Features

### Server Features
- **Multi-client Management**: Manage up to 100 concurrent client connections
- **Command Queue**: Queue commands for batch execution
- **Rate Limiting**: Prevent command flooding
- **Web Dashboard**: Real-time monitoring via web interface
- **Command History**: Track all executed commands
- **Metrics Collection**: Server performance and client statistics
- **Authentication**: Optional token-based authentication
- **Backup System**: Automatic configuration and data backups

### Client Features
- **Cross-platform**: Windows, Linux, macOS support
- **75+ Commands**: Extensive command set for system management
- **Stealth Mode**: Hide process and reduce detection
- **Anti-debugging**: Detect and evade debugging environments
- **Resource Monitoring**: CPU and memory usage tracking
- **Plugin System**: Load and execute custom plugins
- **Database Integration**: SQLite database for data storage
- **Encryption**: File encryption/decryption capabilities
- **Persistence**: Multiple persistence mechanisms

### MITM Features
- **ARP Spoofing**: Redirect network traffic
- **DNS Spoofing**: Manipulate DNS responses
- **SSL Interception**: Decrypt HTTPS traffic (with certificate generation)
- **Credential Harvesting**: Capture HTTP, FTP, SMTP, IMAP credentials
- **Session Hijacking**: Steal cookies and sessions
- **Packet Injection**: Inject custom packets into network traffic
- **Traffic Analysis**: Analyze captured network traffic
- **Web Dashboard**: Real-time statistics and captured data
- **REST API**: Programmatic access to MITM data

##  Available Server Commands

The server provides 75+ commands organized into categories:

### Basic Commands (1-8)
- Send commands to all/specific clients
- System information gathering
- Mining control
- File operations

### File Operations (9-12)
- List files
- Download/upload files
- Delete files/directories

### System Monitoring (13-18)
- Screenshots
- Process management
- System statistics
- Network scanning

### Information Gathering (19-24)
- Installed software
- Environment variables
- Browser history
- Clipboard access

### Advanced Features (25-35)
- Keylogging
- Webcam capture
- Audio recording
- Registry manipulation (Windows)
- Service control
- Password extraction

### Ultra Advanced Features (36-48)
- Remote desktop streaming
- Packet capture
- Reverse shell
- File monitoring
- Steganography
- Anti-forensics

### Extreme Advanced Features (49-60)
- VM detection
- DNS tunneling
- Process injection
- Data exfiltration
- Backdoor creation

### Ultimate Advanced Features (61-75)
- Memory dumping
- Credential harvesting
- Multi-server support
- Plugin management
- Database operations
- Advanced persistence

Type `help` in the server console to see the complete command list.

##  Security Considerations

1. **Authentication**: Enable authentication in `server_config.json` for production use
2. **Encryption**: Enable encryption in client configuration for secure communication
3. **Network Security**: Use VPN or encrypted tunnels for remote connections
4. **Firewall**: Configure firewall rules appropriately
5. **Logging**: Review logs regularly for suspicious activity
6. **Authorization**: Only use on systems you own or have explicit permission to test

##  Project Structure

```
BotnetRozsirovani/
├── server.py              # Server component
├── client.py              # Client agent
├── mitm.py                # MITM framework
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── server_config.json    # Server configuration (auto-generated)
├── client_config.json    # Client configuration (auto-generated)
├── mitm_config.json      # MITM configuration (auto-generated)
├── server.log            # Server logs
├── client.log            # Client logs
└── mitm.log              # MITM logs
```

##  Troubleshooting

### Client cannot connect to server
- Verify server is running
- Check `server_host` in `client_config.json` matches server IP
- Check firewall settings
- Verify port 12345 (or configured port) is open

### MITM not capturing traffic
- Ensure running with administrator/root privileges
- Verify correct network interface is specified
- Check that target and gateway IPs are correct
- Verify ARP spoofing is enabled

### Missing features/errors
- Install all optional dependencies for full functionality
- Check log files for detailed error messages
- Verify Python version is 3.7 or higher
- On Windows, ensure Visual C++ Build Tools are installed for `netifaces`

##  License

This project is provided as-is for educational and authorized security testing purposes. See the legal disclaimer above.

##  Contributing

This is an educational project. Contributions should focus on:
- Bug fixes
- Documentation improvements
- Security enhancements
- Code optimization

##  Additional Resources

- Python Socket Programming: https://docs.python.org/3/library/socket.html
- Scapy Documentation: https://scapy.readthedocs.io/
- Flask Documentation: https://flask.palletsprojects.com/

##  Quick Start Example

1. **Start the server:**
   ```bash
   python server.py
   ```

2. **Configure and start a client:**
   - Edit `client_config.json` with server IP
   - Run: `python client.py`

3. **In server console:**
   - Type `7` to list clients
   - Type `1` to send a command
   - Type `help` for more options

4. **Access web dashboard:**
   - Open browser to `http://localhost:8080`

---

**Remember:** Always ensure you have proper authorization before using this software. Unauthorized access to computer systems is illegal.
