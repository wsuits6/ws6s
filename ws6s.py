#!/usr/bin/env python3
"""
====================================================================
                    WS6S ENTERPRISE SCANNER (v2.0)
         TCP connect, UDP probes, service fingerprinting, OS hints,
                curses-based interactive UI, plugin architecture

Author: Alhassan Osman Wunpini (Wsuits6)
Improved: Enhanced error handling, better architecture, more features

Note: SYN/raw-socket scanning is NOT included for safety reasons.
Use `nmap -sS` if you need SYN scans in an authorized environment.
====================================================================
"""

import argparse
import socket
import time
import json
import sys
import os
import importlib.util
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Optional, Set
from dataclasses import dataclass, field
import threading
import curses
import traceback
from pathlib import Path
import logging
from datetime import datetime

# ---------------------------
# Constants and Configuration
# ---------------------------
SCANNER_NAME = "WS6S ENTERPRISE SCANNER"
VERSION = "2.0"
DEFAULT_PORTS = list(range(1, 1025))
PLUGINS_DIR = "plugins"
OUTPUT_DIR = "scan_results"

# Common port ranges for quick scanning
COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                993, 995, 1723, 3306, 3389, 5900, 8080]
WEB_PORTS = [80, 443, 8000, 8080, 8443, 8888, 9000, 9090]
DATABASE_PORTS = [1433, 1521, 3306, 5432, 6379, 9200, 27017]

# ---------------------------
# Color helpers
# ---------------------------
class Colors:
    """ANSI color codes for terminal output"""
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

def colorize(text: str, color: str, enabled: bool = True) -> str:
    """Apply color to text if enabled"""
    return f"{color}{text}{Colors.RESET}" if enabled else text

# ---------------------------
# Logging setup
# ---------------------------
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with appropriate level"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ---------------------------
# Service database (expandable)
# ---------------------------
SERVICE_DATABASE = {
    # FTP
    20: "ftp-data", 21: "ftp", 
    # SSH/Telnet
    22: "ssh", 23: "telnet",
    # Mail
    25: "smtp", 110: "pop3", 143: "imap", 465: "smtps", 587: "smtp-submission",
    993: "imaps", 995: "pop3s",
    # DNS/DHCP
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    # Web
    80: "http", 443: "https", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
    # Windows
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    445: "microsoft-ds", 3389: "rdp", 5985: "winrm-http", 5986: "winrm-https",
    # Directory services
    389: "ldap", 636: "ldaps", 3268: "ldap-gc", 3269: "ldaps-gc",
    # Network management
    161: "snmp", 162: "snmp-trap", 514: "syslog", 520: "rip",
    # Printing
    515: "lpd", 631: "ipp", 9100: "jetdirect",
    # Databases
    1433: "mssql", 1521: "oracle", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 9200: "elasticsearch", 27017: "mongodb", 11211: "memcached",
    # VPN/Proxy
    1080: "socks", 1194: "openvpn", 1723: "pptp",
    # Remote access
    5900: "vnc", 5901: "vnc-1", 5902: "vnc-2",
    # File sharing
    111: "rpcbind", 2049: "nfs", 873: "rsync",
    # Containers
    2375: "docker", 2376: "docker-tls", 6443: "kubernetes",
    # Monitoring
    9090: "prometheus", 3000: "grafana", 4789: "vxlan",
}

# Banner fingerprinting patterns
BANNER_PATTERNS = {
    "OpenSSH": "SSH",
    "SSH-": "SSH",
    "HTTP/1.": "HTTP",
    "HTTP/2": "HTTP/2",
    "nginx": "nginx",
    "Apache": "Apache",
    "Microsoft-IIS": "IIS",
    "lighttpd": "lighttpd",
    "PostgreSQL": "PostgreSQL",
    "MySQL": "MySQL",
    "MariaDB": "MariaDB",
    "Redis": "Redis",
    "Elasticsearch": "Elasticsearch",
    "MongoDB": "MongoDB",
    "FTP": "FTP",
    "vsFTPd": "vsFTPd",
    "ProFTPD": "ProFTPD",
    "220 ": "SMTP",
    "220-": "SMTP",
    "+OK": "POP3",
    "* OK": "IMAP",
    "RFB ": "VNC",
    "Microsoft Windows RPC": "MS-RPC",
}

# ---------------------------
# Data structures
# ---------------------------
@dataclass
class PortInfo:
    """Information about a scanned port"""
    port: int
    protocol: str  # "tcp" or "udp"
    status: str    # "open", "closed", "filtered", "open|filtered"
    service: str = ""
    banner: str = ""
    confidence: str = "low"  # low, medium, high
    
    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status,
            "service": self.service,
            "banner": self.banner,
            "confidence": self.confidence
        }

@dataclass
class ScanResult:
    """Complete scan results for a target"""
    target: str
    ip: str
    start_time: float
    end_time: float = 0.0
    ports: List[PortInfo] = field(default_factory=list)
    os_hint: str = ""
    error: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    
    def add_port(self, port_info: PortInfo):
        """Thread-safe port addition"""
        with self._lock:
            self.ports.append(port_info)
    
    def get_open_ports(self, protocol: Optional[str] = None) -> List[PortInfo]:
        """Get all open ports, optionally filtered by protocol"""
        with self._lock:
            ports = [p for p in self.ports if p.status == "open"]
            if protocol:
                ports = [p for p in ports if p.protocol == protocol]
            return sorted(ports, key=lambda x: x.port)
    
    def get_stats(self) -> Dict:
        """Get scan statistics"""
        with self._lock:
            total = len(self.ports)
            tcp_ports = [p for p in self.ports if p.protocol == "tcp"]
            udp_ports = [p for p in self.ports if p.protocol == "udp"]
            
            return {
                "total_scanned": total,
                "tcp_scanned": len(tcp_ports),
                "udp_scanned": len(udp_ports),
                "open_ports": len([p for p in self.ports if p.status == "open"]),
                "duration": self.end_time - self.start_time if self.end_time else 0
            }
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON export"""
        stats = self.get_stats()
        return {
            "target": self.target,
            "ip": self.ip,
            "timestamp": datetime.fromtimestamp(self.start_time).isoformat(),
            "duration": stats["duration"],
            "os_hint": self.os_hint,
            "statistics": stats,
            "ports": [p.to_dict() for p in sorted(self.ports, key=lambda x: (x.protocol, x.port))],
            "metadata": self.metadata,
            "error": self.error
        }

# ---------------------------
# Plugin system
# ---------------------------
class PluginBase:
    """
    Base class for scanner plugins.
    
    Plugins can implement:
      - name: str - Plugin name
      - probe_tcp(ip: str, port: int, banner: str) -> Optional[str]
      - probe_udp(ip: str, port: int) -> Optional[str]
      - post_scan(result: ScanResult) -> None
    """
    name = "base"
    
    def probe_tcp(self, ip: str, port: int, banner: str) -> Optional[str]:
        """Analyze TCP banner and return additional info"""
        return None
    
    def probe_udp(self, ip: str, port: int) -> Optional[str]:
        """Probe UDP port and return info"""
        return None
    
    def post_scan(self, result: ScanResult) -> None:
        """Process complete scan results"""
        pass

class PluginManager:
    """Manages plugin discovery and execution"""
    
    def __init__(self, plugins_dir: str):
        self.plugins_dir = Path(plugins_dir)
        self.plugins: List[PluginBase] = []
        
    def discover_plugins(self) -> int:
        """Discover and load plugins from plugins directory"""
        if not self.plugins_dir.exists():
            self.plugins_dir.mkdir(parents=True, exist_ok=True)
            self._create_example_plugin()
            
        loaded = 0
        for plugin_file in self.plugins_dir.glob("plugin_*.py"):
            try:
                plugin = self._load_plugin(plugin_file)
                if plugin:
                    self.plugins.append(plugin)
                    loaded += 1
                    logger.debug(f"Loaded plugin: {plugin.name}")
            except Exception as e:
                logger.warning(f"Failed to load plugin {plugin_file.name}: {e}")
        
        return loaded
    
    def _load_plugin(self, plugin_file: Path) -> Optional[PluginBase]:
        """Load a single plugin file"""
        spec = importlib.util.spec_from_file_location(
            plugin_file.stem, 
            str(plugin_file)
        )
        if not spec or not spec.loader:
            return None
            
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Look for Plugin class or plugin instance
        if hasattr(module, "Plugin"):
            return module.Plugin()
        elif hasattr(module, "plugin"):
            return module.plugin
        
        return None
    
    def _create_example_plugin(self):
        """Create an example plugin template"""
        example_path = self.plugins_dir / "plugin_example.py"
        if example_path.exists():
            return
            
        template = '''"""
Example plugin for WS6S Enterprise Scanner

Plugins can enhance scanning with custom probes and analysis.
"""
from typing import Optional

class Plugin:
    """Example plugin template"""
    name = "example"
    
    def probe_tcp(self, ip: str, port: int, banner: str) -> Optional[str]:
        """
        Analyze TCP banner and return additional information.
        
        Args:
            ip: Target IP address
            port: Port number
            banner: Banner grabbed from the port
            
        Returns:
            Additional service information or None
        """
        # Example: detect specific service versions
        if "MyService" in banner:
            return "Custom Service Detected"
        return None
    
    def probe_udp(self, ip: str, port: int) -> Optional[str]:
        """
        Probe UDP port and return service information.
        
        Args:
            ip: Target IP address
            port: Port number
            
        Returns:
            Service information or None
        """
        # Example: send custom UDP probe
        return None
    
    def post_scan(self, result) -> None:
        """
        Process complete scan results.
        
        Args:
            result: ScanResult object with all port information
        """
        # Example: generate custom report
        open_ports = result.get_open_ports()
        if open_ports:
            print(f"[{self.name}] Found {len(open_ports)} open ports")
'''
        
        example_path.write_text(template)
        logger.info(f"Created example plugin: {example_path}")

# ---------------------------
# Utility functions
# ---------------------------
def parse_port_specification(ports_str: Optional[str]) -> List[int]:
    """
    Parse port specification string into list of port numbers.
    
    Supports:
      - Single ports: "80"
      - Ranges: "1-1024"
      - Lists: "22,80,443"
      - Mixed: "22,80-100,443"
      - Presets: "common", "web", "database"
    """
    if not ports_str:
        return DEFAULT_PORTS.copy()
    
    # Handle presets
    if ports_str.lower() == "common":
        return COMMON_PORTS.copy()
    elif ports_str.lower() == "web":
        return WEB_PORTS.copy()
    elif ports_str.lower() == "database":
        return DATABASE_PORTS.copy()
    elif ports_str.lower() == "all":
        return list(range(1, 65536))
    
    ports: Set[int] = set()
    
    for part in ports_str.split(","):
        part = part.strip()
        
        if not part:
            continue
            
        # Handle ranges
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start.strip()), int(end.strip())
                
                if start > end:
                    start, end = end, start
                    
                # Validate range
                start = max(1, min(start, 65535))
                end = max(1, min(end, 65535))
                
                ports.update(range(start, end + 1))
            except ValueError:
                logger.warning(f"Invalid port range: {part}")
                continue
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    logger.warning(f"Port out of range: {port}")
            except ValueError:
                logger.warning(f"Invalid port number: {part}")
                continue
    
    return sorted(list(ports))

def grab_banner(sock: socket.socket, timeout: float = 0.5) -> str:
    """
    Attempt to grab a service banner from an open socket.
    
    Args:
        sock: Open socket connection
        timeout: Read timeout in seconds
        
    Returns:
        Banner string or empty string
    """
    try:
        sock.settimeout(timeout)
        
        # Some services send banner immediately, others need a probe
        # Try receiving first
        data = sock.recv(4096)
        
        if not data:
            # Try sending a generic probe
            probes = [
                b"GET / HTTP/1.0\r\n\r\n",  # HTTP
                b"\r\n",  # Generic newline
                b"HELP\r\n",  # Generic command
            ]
            
            for probe in probes:
                try:
                    sock.send(probe)
                    data = sock.recv(4096)
                    if data:
                        break
                except:
                    continue
        
        if data:
            # Clean up the banner
            banner = data.decode(errors="ignore").strip()
            # Remove excessive whitespace
            banner = " ".join(banner.split())
            return banner[:1000]  # Limit banner length
            
    except socket.timeout:
        pass
    except Exception as e:
        logger.debug(f"Banner grab error: {e}")
    
    return ""

def fingerprint_service(port: int, banner: str) -> Tuple[str, str]:
    """
    Identify service from port number and banner.
    
    Returns:
        (service_name, confidence) tuple
    """
    # Start with port-based hint
    service = SERVICE_DATABASE.get(port, "")
    confidence = "low" if service else "unknown"
    
    if banner:
        # Try banner pattern matching
        for pattern, name in BANNER_PATTERNS.items():
            if pattern.lower() in banner.lower():
                if service and service.lower() != name.lower():
                    service = f"{service}/{name}"
                else:
                    service = name
                confidence = "high"
                break
        
        if confidence == "low" and service:
            confidence = "medium"
    
    return service, confidence

# ---------------------------
# OS fingerprinting
# ---------------------------
def guess_os(ip: str, open_ports: List[int]) -> str:
    """
    Attempt to guess OS based on open ports and banners.
    
    This is non-invasive and uses heuristics.
    """
    hints = []
    
    # Windows indicators
    windows_ports = {135, 139, 445, 3389, 5985}
    if windows_ports.intersection(open_ports):
        hints.append("Windows")
    
    # Linux/Unix indicators
    unix_ports = {22, 111, 2049}
    if unix_ports.intersection(open_ports):
        hints.append("Linux/Unix")
    
    # Try to grab a banner from SSH (22) or HTTP (80/443)
    for port in [22, 80, 443]:
        if port not in open_ports:
            continue
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            
            if sock.connect_ex((ip, port)) == 0:
                banner = grab_banner(sock, timeout=0.5)
                sock.close()
                
                if banner:
                    # Check for OS indicators in banner
                    banner_lower = banner.lower()
                    
                    if any(x in banner_lower for x in ["ubuntu", "debian", "centos", "rhel", "fedora"]):
                        return f"Linux ({banner[:100]})"
                    elif "windows" in banner_lower or "microsoft" in banner_lower:
                        return f"Windows ({banner[:100]})"
                    elif any(x in banner_lower for x in ["unix", "bsd", "freebsd"]):
                        return f"Unix ({banner[:100]})"
            else:
                sock.close()
                
        except Exception:
            pass
    
    # Return best guess
    if hints:
        return " or ".join(set(hints)) + " (heuristic)"
    
    return "Unknown (insufficient data)"

# ---------------------------
# TCP Scanner
# ---------------------------
def scan_tcp_port(ip: str, port: int, timeout: float, plugins: List[PluginBase]) -> PortInfo:
    """
    Scan a single TCP port.
    
    Args:
        ip: Target IP address
        port: Port to scan
        timeout: Connection timeout
        plugins: List of active plugins
        
    Returns:
        PortInfo object with scan results
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            # Port is open, try to grab banner
            banner = grab_banner(sock, timeout=min(timeout, 0.5))
            sock.close()
            
            # Fingerprint the service
            service, confidence = fingerprint_service(port, banner)
            
            # Allow plugins to enhance detection
            for plugin in plugins:
                try:
                    plugin_info = plugin.probe_tcp(ip, port, banner)
                    if plugin_info:
                        service = f"{service} | {plugin_info}" if service else plugin_info
                        confidence = "high"
                except Exception as e:
                    logger.debug(f"Plugin {plugin.name} error on TCP {port}: {e}")
            
            return PortInfo(
                port=port,
                protocol="tcp",
                status="open",
                service=service,
                banner=banner[:200],  # Limit banner length
                confidence=confidence
            )
        else:
            sock.close()
            return PortInfo(
                port=port,
                protocol="tcp",
                status="closed"
            )
            
    except socket.timeout:
        return PortInfo(
            port=port,
            protocol="tcp",
            status="filtered"
        )
    except Exception as e:
        logger.debug(f"TCP scan error on port {port}: {e}")
        return PortInfo(
            port=port,
            protocol="tcp",
            status="error",
            banner=str(e)[:100]
        )

# ---------------------------
# UDP Scanner
# ---------------------------
def create_udp_probe(port: int) -> bytes:
    """Create protocol-specific UDP probe"""
    
    # DNS (53)
    if port == 53:
        # DNS query for example.com A record
        return (
            b"\x12\x34"  # Transaction ID
            b"\x01\x00"  # Flags: standard query
            b"\x00\x01"  # Questions: 1
            b"\x00\x00\x00\x00\x00\x00"  # Answer/Authority/Additional: 0
            b"\x07example\x03com\x00"  # Query: example.com
            b"\x00\x01"  # Type: A
            b"\x00\x01"  # Class: IN
        )
    
    # NTP (123)
    elif port == 123:
        # NTP request (48 bytes)
        return b"\x1b" + (47 * b"\x00")
    
    # SNMP (161)
    elif port == 161:
        # SNMP GetRequest (SNMPv1, community: public)
        return bytes.fromhex(
            "30 26 02 01 00 04 06 70 75 62 6c 69 63 a0 19 02"
            "04 00 00 00 00 02 01 00 02 01 00 30 0b 30 09 06"
            "05 2b 06 01 02 01 05 00"
        )
    
    # NetBIOS (137)
    elif port == 137:
        return bytes.fromhex("80 f0 00 10 00 01 00 00 00 00 00 00 20 43 4b 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00 00 21 00 01")
    
    # DHCP (67)
    elif port == 67:
        return bytes.fromhex("01 01 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
    
    # Generic probe
    else:
        return b"\x00" * 16

def scan_udp_port(ip: str, port: int, timeout: float, plugins: List[PluginBase]) -> PortInfo:
    """
    Scan a single UDP port using protocol-specific probes.
    
    Note: UDP scanning is inherently unreliable. A lack of response
    doesn't necessarily mean the port is closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Create and send probe
        probe = create_udp_probe(port)
        
        try:
            sock.sendto(probe, (ip, port))
        except Exception as e:
            sock.close()
            return PortInfo(
                port=port,
                protocol="udp",
                status="filtered",
                banner=f"Send error: {str(e)[:50]}"
            )
        
        # Wait for response
        try:
            data, addr = sock.recvfrom(4096)
            sock.close()
            
            # Got a response - port is likely open
            response = data.decode(errors="ignore")[:200]
            service, confidence = fingerprint_service(port, response)
            
            # Plugin enhancement
            for plugin in plugins:
                try:
                    plugin_info = plugin.probe_udp(ip, port)
                    if plugin_info:
                        service = f"{service} | {plugin_info}" if service else plugin_info
                except Exception as e:
                    logger.debug(f"Plugin {plugin.name} error on UDP {port}: {e}")
            
            return PortInfo(
                port=port,
                protocol="udp",
                status="open",
                service=service,
                banner=response,
                confidence=confidence
            )
            
        except socket.timeout:
            # No response - could be open|filtered
            sock.close()
            service = SERVICE_DATABASE.get(port, "")
            return PortInfo(
                port=port,
                protocol="udp",
                status="open|filtered",
                service=service,
                confidence="low"
            )
            
    except Exception as e:
        logger.debug(f"UDP scan error on port {port}: {e}")
        return PortInfo(
            port=port,
            protocol="udp",
            status="error",
            banner=str(e)[:100]
        )

# ---------------------------
# Main scanner orchestrator
# ---------------------------
class PortScanner:
    """Main port scanner class"""
    
    def __init__(self, 
                 timeout: float = 1.0,
                 threads: int = 200,
                 verbose: bool = False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.plugin_manager = PluginManager(PLUGINS_DIR)
        
    def load_plugins(self) -> int:
        """Load scanner plugins"""
        return self.plugin_manager.discover_plugins()
    
    def scan(self,
             target: str,
             ports: List[int],
             scan_tcp: bool = True,
             scan_udp: bool = False,
             progress_callback = None) -> ScanResult:
        """
        Perform port scan on target.
        
        Args:
            target: Hostname or IP address
            ports: List of ports to scan
            scan_tcp: Enable TCP scanning
            scan_udp: Enable UDP scanning
            progress_callback: Optional callback for progress updates
            
        Returns:
            ScanResult object
        """
        # Resolve target
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            result = ScanResult(
                target=target,
                ip="",
                start_time=time.time(),
                error=f"Could not resolve hostname: {e}"
            )
            result.end_time = time.time()
            return result
        
        logger.info(f"Scanning {target} ({ip})")
        logger.info(f"Ports: {len(ports)}, TCP: {scan_tcp}, UDP: {scan_udp}")
        
        result = ScanResult(
            target=target,
            ip=ip,
            start_time=time.time()
        )
        
        total_tasks = (len(ports) if scan_tcp else 0) + (len(ports) if scan_udp else 0)
        completed_tasks = 0
        
        # TCP scanning
        if scan_tcp:
            logger.info("Starting TCP scan...")
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(
                        scan_tcp_port, 
                        ip, 
                        port, 
                        self.timeout, 
                        self.plugin_manager.plugins
                    ): port 
                    for port in ports
                }
                
                for future in as_completed(futures):
                    try:
                        port_info = future.result()
                        result.add_port(port_info)
                        
                        completed_tasks += 1
                        if progress_callback:
                            progress_callback(completed_tasks, total_tasks, port_info)
                            
                    except Exception as e:
                        port = futures[future]
                        logger.error(f"Error scanning TCP port {port}: {e}")
        
        # UDP scanning
        if scan_udp:
            logger.info("Starting UDP scan...")
            
            # Use fewer threads for UDP to avoid overwhelming the network
            udp_threads = min(self.threads // 2, 50)
            
            with ThreadPoolExecutor(max_workers=udp_threads) as executor:
                futures = {
                    executor.submit(
                        scan_udp_port,
                        ip,
                        port,
                        self.timeout * 2,  # UDP needs more time
                        self.plugin_manager.plugins
                    ): port
                    for port in ports
                }
                
                for future in as_completed(futures):
                    try:
                        port_info = future.result()
                        result.add_port(port_info)
                        
                        completed_tasks += 1
                        if progress_callback:
                            progress_callback(completed_tasks, total_tasks, port_info)
                            
                    except Exception as e:
                        port = futures[future]
                        logger.error(f"Error scanning UDP port {port}: {e}")
        
        # OS fingerprinting
        open_ports = [p.port for p in result.get_open_ports("tcp")]
        if open_ports:
            result.os_hint = guess_os(ip, open_ports)
        
        result.end_time = time.time()
        
        # Run post-scan plugin hooks
        for plugin in self.plugin_manager.plugins:
            try:
                plugin.post_scan(result)
            except Exception as e:
                logger.error(f"Plugin {plugin.name} post_scan error: {e}")
        
        return result

# ---------------------------
# Curses UI
# ---------------------------
class CursesUI:
    """Interactive curses-based UI for scan results"""
    
    def __init__(self, stdscr, result: ScanResult):
        self.stdscr = stdscr
        self.result = result
        self.height = 0
        self.width = 0
        self.selected_idx = 0
        self.scroll_offset = 0
        self.filter_mode = "open"  # open, all, tcp, udp
        self.sorted_ports: List[PortInfo] = []
        
        # Initialize curses
        curses.curs_set(0)  # Hide cursor
        self.stdscr.keypad(True)
        
        # Initialize colors if available
        if curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
            curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
            curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
            curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        
        self.update_dimensions()
        self.update_port_list()
    
    def update_dimensions(self):
        """Update screen dimensions"""
        self.height, self.width = self.stdscr.getmaxyx()
    
    def update_port_list(self):
        """Update the filtered and sorted port list"""
        if self.filter_mode == "open":
            self.sorted_ports = self.result.get_open_ports()
        elif self.filter_mode == "tcp":
            self.sorted_ports = [p for p in self.result.ports if p.protocol == "tcp"]
        elif self.filter_mode == "udp":
            self.sorted_ports = [p for p in self.result.ports if p.protocol == "udp"]
        else:  # all
            self.sorted_ports = sorted(self.result.ports, key=lambda x: (x.protocol, x.port))
    
    def draw_header(self):
        """Draw the header with scan information"""
        try:
            # Title
            title = f" {SCANNER_NAME} v{VERSION} "
            self.stdscr.addstr(0, 0, title.center(self.width)[:self.width], curses.A_REVERSE)
            
            # Target info
            target_line = f" Target: {self.result.target} ({self.result.ip}) "
            self.stdscr.addstr(1, 0, target_line[:self.width])
            
            # Stats
            stats = self.result.get_stats()
            stats_line = f" Open: {stats['open_ports']} | Scanned: {stats['total_scanned']} | Duration: {stats['duration']:.1f}s "
            self.stdscr.addstr(2, 0, stats_line[:self.width])
            
            # OS hint
            if self.result.os_hint:
                os_line = f" OS: {self.result.os_hint} "
                self.stdscr.addstr(3, 0, os_line[:self.width])
            
        except curses.error:
            pass
    
    def draw_port_list(self):
        """Draw the list of ports"""
        start_row = 5
        list_height = self.height - start_row - 2
        
        # Column headers
        try:
            header = f" {'Proto':5} {'Port':7} {'Status':12} {'Service':20} {'Banner':30} "
            self.stdscr.addstr(start_row - 1, 0, header[:self.width], curses.A_BOLD)
        except curses.error:
            pass
        
        # Port entries
        for i in range(list_height):
            row = start_row + i
            idx = self.scroll_offset + i
            
            if idx >= len(self.sorted_ports):
                try:
                    self.stdscr.addstr(row, 0, " " * (self.width - 1))
                except curses.error:
                    pass
                continue
            
            port = self.sorted_ports[idx]
            
            # Format line
            proto = port.protocol.upper()
            status = port.status
            service = port.service[:20] if port.service else ""
            banner = port.banner[:30] if port.banner else ""
            
            line = f" {proto:5} {port.port:7d} {status:12} {service:20} {banner:30} "
            line = line[:self.width - 1]
            
            # Color based on status
            attr = curses.A_NORMAL
            if port.status == "open":
                attr = curses.color_pair(1)  # Green
            elif port.status == "closed":
                attr = curses.color_pair(2)  # Red
            elif "filtered" in port.status:
                attr = curses.color_pair(3)  # Yellow
            
            # Highlight selected
            if idx == self.selected_idx:
                attr |= curses.A_REVERSE
            
            try:
                self.stdscr.addstr(row, 0, line, attr)
            except curses.error:
                pass
    
    def draw_footer(self):
        """Draw the footer with controls"""
        try:
            controls = f" Filter: {self.filter_mode.upper()} | ↑/↓: Navigate | o:Open a:All t:TCP u:UDP | q:Quit "
            self.stdscr.addstr(self.height - 1, 0, controls[:self.width], curses.A_REVERSE)
        except curses.error:
            pass
    
    def refresh_screen(self):
        """Redraw the entire screen"""
        self.stdscr.erase()
        self.update_dimensions()
        self.draw_header()
        self.draw_port_list()
        self.draw_footer()
        self.stdscr.refresh()
    
    def run(self):
        """Main UI loop"""
        self.refresh_screen()
        
        while True:
            try:
                key = self.stdscr.getch()
                
                # Quit
                if key == ord('q') or key == ord('Q'):
                    break
                
                # Filter modes
                elif key == ord('o') or key == ord('O'):
                    self.filter_mode = "open"
                    self.update_port_list()
                    self.selected_idx = 0
                    self.scroll_offset = 0
                elif key == ord('a') or key == ord('A'):
                    self.filter_mode = "all"
                    self.update_port_list()
                    self.selected_idx = 0
                    self.scroll_offset = 0
                elif key == ord('t') or key == ord('T'):
                    self.filter_mode = "tcp"
                    self.update_port_list()
                    self.selected_idx = 0
                    self.scroll_offset = 0
                elif key == ord('u') or key == ord('U'):
                    self.filter_mode = "udp"
                    self.update_port_list()
                    self.selected_idx = 0
                    self.scroll_offset = 0
                
                # Navigation
                elif key == curses.KEY_UP:
                    if self.selected_idx > 0:
                        self.selected_idx -= 1
                        if self.selected_idx < self.scroll_offset:
                            self.scroll_offset = self.selected_idx
                
                elif key == curses.KEY_DOWN:
                    if self.selected_idx < len(self.sorted_ports) - 1:
                        self.selected_idx += 1
                        list_height = self.height - 7
                        if self.selected_idx >= self.scroll_offset + list_height:
                            self.scroll_offset = self.selected_idx - list_height + 1
                
                elif key == curses.KEY_PPAGE:  # Page Up
                    self.selected_idx = max(0, self.selected_idx - 10)
                    self.scroll_offset = max(0, self.scroll_offset - 10)
                
                elif key == curses.KEY_NPAGE:  # Page Down
                    self.selected_idx = min(len(self.sorted_ports) - 1, self.selected_idx + 10)
                    list_height = self.height - 7
                    if self.selected_idx >= self.scroll_offset + list_height:
                        self.scroll_offset = min(len(self.sorted_ports) - list_height, self.scroll_offset + 10)
                
                elif key == curses.KEY_HOME:
                    self.selected_idx = 0
                    self.scroll_offset = 0
                
                elif key == curses.KEY_END:
                    self.selected_idx = len(self.sorted_ports) - 1
                    list_height = self.height - 7
                    self.scroll_offset = max(0, len(self.sorted_ports) - list_height)
                
                # Refresh display
                self.refresh_screen()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"UI error: {e}")
                break

# ---------------------------
# Output functions
# ---------------------------
def print_scan_results(result: ScanResult, color_enabled: bool = True):
    """Print scan results to console"""
    
    print("\n" + "=" * 70)
    print(colorize(f" {SCANNER_NAME} - Scan Results ", Colors.CYAN + Colors.BOLD, color_enabled))
    print("=" * 70)
    
    print(f"\nTarget:   {result.target} ({result.ip})")
    print(f"Started:  {datetime.fromtimestamp(result.start_time).strftime('%Y-%m-%d %H:%M:%S')}")
    
    stats = result.get_stats()
    print(f"Duration: {stats['duration']:.2f}s")
    print(f"Scanned:  {stats['total_scanned']} ports (TCP: {stats['tcp_scanned']}, UDP: {stats['udp_scanned']})")
    print(f"Open:     {stats['open_ports']}")
    
    if result.os_hint:
        print(f"OS Hint:  {result.os_hint}")
    
    # Open TCP ports
    open_tcp = result.get_open_ports("tcp")
    if open_tcp:
        print(f"\n{colorize('TCP Ports (Open):', Colors.GREEN + Colors.BOLD, color_enabled)}")
        print(f"{'Port':7} {'Service':25} {'Confidence':12} {'Banner':40}")
        print("-" * 85)
        
        for port in open_tcp:
            service = port.service[:25] if port.service else "-"
            banner = port.banner[:40] if port.banner else "-"
            print(colorize(
                f"{port.port:7d} {service:25} {port.confidence:12} {banner:40}",
                Colors.GREEN,
                color_enabled
            ))
    
    # Open UDP ports
    open_udp = result.get_open_ports("udp")
    if open_udp:
        print(f"\n{colorize('UDP Ports (Open/Open|Filtered):', Colors.YELLOW + Colors.BOLD, color_enabled)}")
        print(f"{'Port':7} {'Status':15} {'Service':25} {'Banner':30}")
        print("-" * 80)
        
        for port in sorted(open_udp, key=lambda x: x.port):
            service = port.service[:25] if port.service else "-"
            banner = port.banner[:30] if port.banner else "-"
            print(colorize(
                f"{port.port:7d} {port.status:15} {service:25} {banner:30}",
                Colors.YELLOW,
                color_enabled
            ))
    
    print("\n" + "=" * 70)
    
    # Security note
    if not open_tcp and not open_udp:
        print(colorize("\nNo open ports found.", Colors.YELLOW, color_enabled))
    
    print(colorize("\n[*] For SYN scans, use: nmap -sS <target> (requires privileges)", Colors.CYAN, color_enabled))

def save_results(result: ScanResult, output_format: str = "json"):
    """Save scan results to file"""
    
    # Create output directory
    output_dir = Path(OUTPUT_DIR)
    output_dir.mkdir(exist_ok=True)
    
    # Generate filename
    timestamp = datetime.fromtimestamp(result.start_time).strftime('%Y%m%d_%H%M%S')
    safe_target = result.target.replace('.', '_').replace(':', '_')
    filename = f"scan_{safe_target}_{timestamp}.{output_format}"
    filepath = output_dir / filename
    
    # Save based on format
    if output_format == "json":
        with open(filepath, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
    elif output_format == "txt":
        with open(filepath, 'w') as f:
            # Redirect print to file
            import sys
            old_stdout = sys.stdout
            sys.stdout = f
            print_scan_results(result, color_enabled=False)
            sys.stdout = old_stdout
    
    logger.info(f"Results saved to: {filepath}")
    return filepath

# ---------------------------
# Main CLI
# ---------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="ws6s-scanner",
        description=f"{SCANNER_NAME} - Enterprise Port Scanner with Plugins",
        epilog="For SYN scans, use nmap -sS with proper authorization.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target
    parser.add_argument(
        "target",
        help="Target hostname or IP address"
    )
    
    # Port specification
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan (e.g., 22,80,443 or 1-1024 or 'common' or 'web')",
        default=None
    )
    
    # Scan options
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )
    
    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=200,
        help="Number of worker threads (default: 200)"
    )
    
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Enable UDP port scanning (slower)"
    )
    
    parser.add_argument(
        "--tcp-only",
        action="store_true",
        help="Scan TCP ports only (default)"
    )
    
    # Scan profiles
    parser.add_argument(
        "--profile",
        choices=["fast", "normal", "stealth"],
        default="normal",
        help="Scan profile (fast: fewer threads, short timeout; stealth: more threads, longer timeout)"
    )
    
    # UI and output
    parser.add_argument(
        "--curses",
        action="store_true",
        help="Launch interactive curses UI after scan"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    
    parser.add_argument(
        "--save",
        choices=["json", "txt"],
        help="Save results to file in specified format"
    )
    
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    
    # Plugins
    parser.add_argument(
        "--plugins",
        action="store_true",
        help="Enable plugin system"
    )
    
    # Verbosity
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"{SCANNER_NAME} v{VERSION}"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    global logger
    logger = setup_logging(args.verbose)
    
    # Apply scan profiles
    if args.profile == "fast":
        args.threads = min(args.threads, 100)
        args.timeout = 0.5
    elif args.profile == "stealth":
        args.threads = min(args.threads, 50)
        args.timeout = 2.0
    
    # Parse ports
    try:
        ports = parse_port_specification(args.ports)
        if not ports:
            print(colorize("[!] No valid ports specified", Colors.RED, not args.no_color))
            sys.exit(1)
        logger.info(f"Scanning {len(ports)} ports")
    except Exception as e:
        print(colorize(f"[!] Error parsing ports: {e}", Colors.RED, not args.no_color))
        sys.exit(1)
    
    # Create scanner
    scanner = PortScanner(
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose
    )
    
    # Load plugins if enabled
    if args.plugins:
        plugin_count = scanner.load_plugins()
        logger.info(f"Loaded {plugin_count} plugin(s)")
    
    # Progress callback for real-time updates
    def progress_callback(completed, total, port_info):
        if port_info.status == "open":
            msg = colorize(
                f"[+] {port_info.protocol.upper()} {port_info.port} OPEN - {port_info.service}",
                Colors.GREEN,
                not args.no_color
            )
            print(msg)
    
    # Run scan
    print(colorize(f"\n[*] Starting scan of {args.target}...\n", Colors.CYAN, not args.no_color))
    
    try:
        result = scanner.scan(
            target=args.target,
            ports=ports,
            scan_tcp=not args.udp or not args.tcp_only,
            scan_udp=args.udp,
            progress_callback=progress_callback if args.verbose else None
        )
        
        if result.error:
            print(colorize(f"\n[!] Scan error: {result.error}", Colors.RED, not args.no_color))
            sys.exit(1)
        
    except KeyboardInterrupt:
        print(colorize("\n[!] Scan interrupted by user", Colors.YELLOW, not args.no_color))
        sys.exit(130)
    except Exception as e:
        print(colorize(f"\n[!] Unexpected error: {e}", Colors.RED, not args.no_color))
        if args.verbose:
            traceback.print_exc()
        sys.exit(2)
    
    # Output results
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_scan_results(result, color_enabled=not args.no_color)
    
    # Save results
    if args.save:
        save_results(result, args.save)
    
    # Launch curses UI
    if args.curses:
        try:
            print(colorize("\n[*] Launching interactive UI (press 'q' to quit)...", Colors.CYAN, not args.no_color))
            time.sleep(1)
            curses.wrapper(lambda stdscr: CursesUI(stdscr, result).run())
        except Exception as e:
            logger.error(f"Curses UI error: {e}")
            if args.verbose:
                traceback.print_exc()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)