#!/usr/bin/env python3
"""
====================================================================
                    WS6S ENTERPRISE SCANNER (v1)
         TCP connect, UDP probes, service fingerprinting, OS hints,
                curses-based interactive UI, plugin architecture

Author: Alhassan Osman Wunpini (Wsuits6)
Note: SYN/raw-socket scanning is NOT included for safety reasons.
Use `nmap -sS` if you need SYN scans in an authorized environment.
====================================================================
"""

import argparse
import socket
import time
import json
import random
import sys
import os
import importlib.util
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Optional
import threading
import curses
import traceback

# ---------------------------
# Config / defaults
# ---------------------------
DEFAULT_PORTS = list(range(1, 1025))
PLUGINS_DIR = "plugins"
SCANNER_NAME = "WS6S ENTERPRISE SCANNER"
VERSION = "1.0"

# ---------------------------
# Color helpers (for normal output)
# ---------------------------
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"

def c(text, color, enabled=True):
    return f"{color}{text}{Colors.RESET}" if enabled else text

# ---------------------------
# Basic service hints and fingerprints (expandable)
# ---------------------------
SERVICE_HINTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    514: "syslog", 631: "ipp", 873: "rsync", 990: "ftps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 9200: "elasticsearch", 11211: "memcached"
}

# Small banner pattern database for service fingerprinting
BANNER_PATTERNS = {
    "OpenSSH": "SSH",
    "SSH-": "SSH",
    "HTTP/1.1": "HTTP",
    "HTTP/1.0": "HTTP",
    "nginx": "nginx",
    "Apache": "Apache",
    "Microsoft-IIS": "IIS",
    "PostgreSQL": "PostgreSQL",
    "MySQL": "MySQL",
    "Redis": "Redis",
    "Elasticsearch": "Elasticsearch",
    "FTP": "FTP",
    "220 ": "SMTP",
    "220-": "SMTP",
    "DNS": "DNS"
}

# ---------------------------
# Plugin system
# ---------------------------
class PluginBase:
    """
    Plugins may implement:
      - probe_udp(ip, port) -> Optional[str]
      - probe_tcp_banner(ip, port, banner) -> Optional[str]
      - post_scan(results) -> None
    """
    name = "base"

def discover_plugins(directory: str) -> List[PluginBase]:
    plugins = []
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
        # create an example plugin stub
        stub = os.path.join(directory, "plugin_example.py")
        if not os.path.exists(stub):
            with open(stub, "w") as f:
                f.write("# Example plugin for WS6S scanner\n"
                        "from typing import Optional\n"
                        "class Plugin:\n"
                        "    name = 'example'\n"
                        "    def probe_udp(self, ip: str, port: int) -> Optional[str]:\n"
                        "        return None\n"
                        "    def probe_tcp_banner(self, ip: str, port: int, banner: str) -> Optional[str]:\n"
                        "        return None\n"
                        "    def post_scan(self, results):\n"
                        "        pass\n")
    for fn in os.listdir(directory):
        if not fn.startswith("plugin_") or not fn.endswith(".py"):
            continue
        path = os.path.join(directory, fn)
        spec = importlib.util.spec_from_file_location(fn[:-3], path)
        try:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            # plugin can be class Plugin or instance plugin
            plugin = None
            if hasattr(mod, "Plugin"):
                plugin = getattr(mod, "Plugin")()
            elif hasattr(mod, "plugin"):
                plugin = getattr(mod, "plugin")
            if plugin:
                plugins.append(plugin)
        except Exception as e:
            print(f"Plugin load error {fn}: {e}")
    return plugins

# ---------------------------
# Utility functions
# ---------------------------
def parse_ports(ports_str: Optional[str]) -> List[int]:
    if not ports_str:
        return DEFAULT_PORTS.copy()
    s = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a = int(a); b = int(b)
                if a > b:
                    a, b = b, a
                for p in range(max(1, a), min(65535, b) + 1):
                    s.add(p)
            except:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    s.add(p)
            except:
                continue
    return sorted(s)

def grab_banner(sock: socket.socket, timeout=0.3) -> str:
    try:
        sock.settimeout(timeout)
        data = sock.recv(4096)
        if not data:
            return ""
        return data.decode(errors="ignore").strip().replace("\r", " ").replace("\n", " ")
    except:
        return ""

# ---------------------------
# OS fingerprinting heuristics
# (non-invasive - ttl & window size heuristics)
# ---------------------------
def os_hint_from_socket(ip: str) -> str:
    """
    Make a short TCP connection to an open-ish port (80/443) then inspect
    the remote TTL (approximate) using a new socket's recvfrom? We cannot
    read TTL from user-level sockets portably. Instead we provide heuristics
    based on banner & TCP behavior and inform the user this is probabilistic.
    """
    # We'll attempt to connect to 80 or 443 to collect banner if present,
    # then use banner patterns to guess OS.
    for p in (80, 443, 22):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            res = s.connect_ex((ip, p))
            if res == 0:
                b = grab_banner(s, timeout=0.2)
                s.close()
                if "Microsoft-IIS" in b or "MS-IIS" in b or "Windows" in b:
                    return "Likely Windows (banner hint)"
                if "Apache" in b or "nginx" in b or "Ubuntu" in b or "Debian" in b:
                    return "Likely Linux/Unix (banner hint)"
                # fallback
                return "Unknown (banner read, inconclusive)"
            s.close()
        except:
            continue
    return "No fingerprint data (passive hints unavailable)"

# ---------------------------
# TCP connect scanner
# ---------------------------
def tcp_scan_single(ip: str, port: int, timeout: float) -> Tuple[int, str, Optional[str]]:
    """
    Returns (port, status, info)
     - status: "open" | "closed" | "filtered"
     - info: banner / fingerprint
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        if r == 0:
            banner = grab_banner(s, timeout=0.3)
            s.close()
            hint = SERVICE_HINTS.get(port, "")
            # plugin-based fingerprinting optionally applied by caller
            if banner:
                # fingerprint via banner patterns
                for pat, name in BANNER_PATTERNS.items():
                    if pat in banner:
                        hint = f"{hint} | {name}" if hint else name
                        break
                # append raw banner snippet
                if banner and len(banner) > 0:
                    hint = f"{hint} | {banner[:250]}" if hint else banner[:250]
            return port, "open", hint
        else:
            s.close()
            return port, "closed", ""
    except Exception:
        return port, "filtered", ""

# ---------------------------
# UDP scanner (probe-based)
# ---------------------------
# We'll implement probes for common UDP services: DNS(53), NTP(123), SNMP(161), MDNS/SSDP examples.
def udp_probe(ip: str, port: int, timeout: float) -> Tuple[int, str, Optional[str]]:
    """
    Returns (port, status, info)
     - status: "open", "closed" (ICMP port unreachable), "open|filtered" (no response)
     - info: payload response or plugin info
    Note: ICMP detection isn't fully reliable from userland sockets. We use recvfrom timeouts.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        probe_payload = b""
        # craft light probes for specific services
        if port == 53:
            # simple DNS query for A record of example.com (not full DNS lib)
            probe_payload = b"\x12\x34" + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + \
                b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
        elif port == 123:
            # NTP request (48 bytes)
            probe_payload = b"\x1b" + 47 * b"\0"
        elif port == 161:
            # SNMP basic get (v1) stub (probably won't get reply without community exact)
            probe_payload = b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        else:
            # generic small payload
            probe_payload = b"\x00"
        try:
            s.sendto(probe_payload, (ip, port))
        except Exception:
            s.close()
            return port, "open|filtered", ""
        # wait for any response
        try:
            data, addr = s.recvfrom(4096)
            s.close()
            resp = data.decode(errors="ignore").strip()
            # fingerprint from response
            for pat, name in BANNER_PATTERNS.items():
                if pat in resp:
                    return port, "open", name + " | " + (resp[:250] if resp else "")
            return port, "open", resp[:250] if resp else ""
        except socket.timeout:
            s.close()
            return port, "open|filtered", ""
        except Exception:
            s.close()
            return port, "open|filtered", ""
    except Exception:
        return port, "filtered", ""

# ---------------------------
# Orchestrator
# ---------------------------
class ScanResult:
    def __init__(self, ip):
        self.ip = ip
        self.tcp = {}  # port -> (status, info)
        self.udp = {}
        self.lock = threading.Lock()
        self.meta = {}

    def add_tcp(self, port, status, info):
        with self.lock:
            self.tcp[port] = (status, info)

    def add_udp(self, port, status, info):
        with self.lock:
            self.udp[port] = (status, info)

def run_scans(target: str,
              ports: List[int],
              timeout: float,
              threads: int,
              udp_enabled: bool,
              tcp_only_ports: Optional[List[int]],
              plugins: List,
              profile: str,
              verbose: bool,
              json_out: bool,
              color: bool) -> ScanResult:

    # Resolve
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        raise RuntimeError(f"Could not resolve {target}: {e}")

    result = ScanResult(ip)
    start = time.time()

    # OS hint
    result.meta["os_hint"] = os_hint_from_socket(ip)

    # Threaded TCP scanning
    def tcp_worker(port):
        try:
            port, status, info = tcp_scan_single(ip, port, timeout)
            # plugin hooks: allow plugin to modify or add info
            for plugin in plugins:
                try:
                    if hasattr(plugin, "probe_tcp_banner"):
                        alt = plugin.probe_tcp_banner(ip, port, info)
                        if alt:
                            info = f"{info} | {alt}" if info else alt
                except Exception:
                    pass
            result.add_tcp(port, status, info)
            return port, status
        except Exception as e:
            result.add_tcp(port, "error", str(e))
            return port, "error"

    with ThreadPoolExecutor(max_workers=threads) as ex:
        # TCP scans first
        tcp_futures = {ex.submit(tcp_worker, p): p for p in ports}
        for fut in as_completed(tcp_futures):
            # simply iterate so we can show progress in UI
            try:
                fut.result()
            except Exception:
                pass

    # UDP scanning if enabled (probe only for selected ports)
    if udp_enabled:
        udp_ports = ports if not tcp_only_ports else [p for p in ports if p in tcp_only_ports]
        # to avoid total flood, use smaller thread count
        udp_threads = max(4, min(threads // 4, 50))
        def udp_worker(port):
            try:
                p, status, info = udp_probe(ip, port, timeout)
                for plugin in plugins:
                    try:
                        if hasattr(plugin, "probe_udp"):
                            alt = plugin.probe_udp(ip, port)
                            if alt:
                                info = f"{info} | {alt}" if info else alt
                    except Exception:
                        pass
                result.add_udp(p, status, info)
            except Exception:
                result.add_udp(port, "error", "")

        with ThreadPoolExecutor(max_workers=udp_threads) as uex:
            ufs = {uex.submit(udp_worker, p): p for p in udp_ports}
            for fut in as_completed(ufs):
                try:
                    fut.result()
                except:
                    pass

    result.meta["elapsed"] = time.time() - start
    result.meta["scanned_ports_count"] = len(ports)
    return result

# ---------------------------
# Curses-based UI
# ---------------------------
class CursesUI:
    def __init__(self, stdscr, scanner):
        self.stdscr = stdscr
        self.scanner = scanner
        curses.curs_set(0)
        self.height, self.width = self.stdscr.getmaxyx()
        self.filter_mode = "all"  # all | tcp | udp
        self.selected_idx = 0
        self.items = []
        self.lock = threading.Lock()

    def draw_banner(self):
        header = f" {SCANNER_NAME}  v{VERSION} "
        target_line = f" Target: {self.scanner['target']} ({self.scanner['ip']}) "
        status_line = f" Threads:{self.scanner['threads']} Timeout:{self.scanner['timeout']} "
        self.stdscr.addstr(0, 0, header[:self.width - 1], curses.A_REVERSE)
        self.stdscr.addstr(1, 0, target_line[:self.width - 1], curses.A_BOLD)
        self.stdscr.addstr(2, 0, status_line[:self.width - 1])

    def build_items(self):
        items = []
        # combine tcp and udp results
        tcp = sorted(self.scanner['result'].tcp.items())
        udp = sorted(self.scanner['result'].udp.items())
        if self.filter_mode in ("all", "tcp"):
            for p, (st, info) in tcp:
                items.append(("TCP", p, st, info))
        if self.filter_mode in ("all", "udp"):
            for p, (st, info) in udp:
                items.append(("UDP", p, st, info))
        self.items = sorted(items, key=lambda x: (x[0], x[1]))

    def draw_list(self):
        start_row = 4
        max_rows = self.height - start_row - 2
        for i in range(max_rows):
            line_no = i
            y = start_row + i
            if i < len(self.items):
                proto, port, stat, info = self.items[i]
                status_icon = "OPEN " if stat == "open" else ("CLOSED" if stat == "closed" else stat.upper())
                text = f"{proto:3s} {port:5d} {status_icon:8s} {info[:self.width-25]}"
                if i == self.selected_idx:
                    self.stdscr.addstr(y, 0, text.ljust(self.width - 1)[:self.width - 1], curses.A_REVERSE)
                else:
                    self.stdscr.addstr(y, 0, text.ljust(self.width - 1)[:self.width - 1])
            else:
                self.stdscr.addstr(y, 0, " ".ljust(self.width - 1))

    def draw_footer(self):
        foot = f" Filter: {self.filter_mode}  Items: {len(self.items)}  Elapsed: {self.scanner['result'].meta.get('elapsed',0):.1f}s "
        self.stdscr.addstr(self.height - 1, 0, foot[:self.width - 1], curses.A_REVERSE)

    def refresh(self):
        with self.lock:
            self.stdscr.erase()
            self.height, self.width = self.stdscr.getmaxyx()
            self.draw_banner()
            self.build_items()
            self.draw_list()
            self.draw_footer()
            self.stdscr.refresh()

    def run(self):
        self.refresh()
        while True:
            try:
                k = self.stdscr.getch()
                if k == ord("q"):
                    break
                elif k == ord("t"):
                    self.filter_mode = "tcp"
                elif k == ord("u"):
                    self.filter_mode = "udp"
                elif k == ord("a"):
                    self.filter_mode = "all"
                elif k == curses.KEY_DOWN:
                    if self.selected_idx + 1 < len(self.items):
                        self.selected_idx += 1
                elif k == curses.KEY_UP:
                    if self.selected_idx > 0:
                        self.selected_idx -= 1
                # refresh after keystroke
                self.refresh()
            except KeyboardInterrupt:
                break
            except Exception:
                # if curses throws during resize etc, ignore and continue
                pass


# ---------------------------
# Output helpers
# ---------------------------
def print_summary(result: ScanResult, target: str, color_enabled: bool):
    print("=" * 70)
    print(f"{SCANNER_NAME} - Summary for {target} ({result.ip})")
    print(f"OS hint: {result.meta.get('os_hint')}")
    print(f"Elapsed: {result.meta.get('elapsed'):.2f}s Scanned ports: {result.meta.get('scanned_ports_count')}")
    print("-" * 70)
    if result.tcp:
        print("TCP Results (open/closed/filtered):")
        for p in sorted(result.tcp.keys()):
            st, info = result.tcp[p]
            if st == "open":
                print(c(f"  TCP {p:5d} OPEN    {info}", Colors.GREEN, color_enabled))
        print()
    if result.udp:
        print("UDP Results (open/closed/open|filtered):")
        for p in sorted(result.udp.keys()):
            st, info = result.udp[p]
            if st == "open":
                print(c(f"  UDP {p:5d} OPEN    {info}", Colors.GREEN, color_enabled))
            elif st == "open|filtered":
                print(c(f"  UDP {p:5d} OPEN|FILTERED", Colors.YELLOW, color_enabled))
    print("=" * 70)

# ---------------------------
# Main CLI
# ---------------------------
def main():
    parser = argparse.ArgumentParser(prog="ws6s-enterprise-scanner", description="WS6S Enterprise Scanner (TCP+UDP+UI+Plugins).")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-p", "--ports", help="Ports: e.g. 22,80,1-1024", default=None)
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Per-socket timeout (s)")
    parser.add_argument("-T", "--threads", type=int, default=200, help="Worker threads")
    parser.add_argument("--udp", action="store_true", help="Enable UDP probing")
    parser.add_argument("--profile", choices=["fast", "normal", "stealth"], default="normal")
    parser.add_argument("--curses", action="store_true", help="Enable curses-based interactive UI (best with terminal)")
    parser.add_argument("--json", action="store_true", help="Output JSON after scan")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--plugins", action="store_true", help="Load plugins from ./plugins/")
    args = parser.parse_args()

    # Apply profiles
    if args.profile == "fast":
        args.threads = max(50, args.threads)
        args.timeout = 0.4
    elif args.profile == "stealth":
        args.threads = min(30, args.threads)
        args.timeout = 1.5

    ports = parse_ports(args.ports)
    plugins = discover_plugins(PLUGINS_DIR) if args.plugins else []

    # run the scanner (blocking)
    try:
        result = run_scans(
            target=args.target,
            ports=ports,
            timeout=args.timeout,
            threads=args.threads,
            udp_enabled=args.udp,
            tcp_only_ports=None,
            plugins=plugins,
            profile=args.profile,
            verbose=args.verbose,
            json_out=args.json,
            color=not args.no_color
        )
    except RuntimeError as e:
        print(f"[!] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(2)

    # plugin post-scan hooks
    for plugin in plugins:
        try:
            if hasattr(plugin, "post_scan"):
                plugin.post_scan(result)
        except Exception:
            pass

    # print or UI
    if args.curses:
        # prepare scanner descriptor for UI
        scanner_desc = {
            "target": args.target,
            "ip": result.ip,
            "threads": args.threads,
            "timeout": args.timeout,
            "result": result
        }
        try:
            curses.wrapper(lambda stdscr: CursesUI(stdscr, scanner_desc).run())
        except Exception as e:
            print(f"[!] Curses UI failed: {e}")

    # JSON output
    if args.json:
        out = {
            "target": args.target,
            "ip": result.ip,
            "meta": result.meta,
            "tcp": {str(p): {"status": s, "info": i} for p, (s, i) in result.tcp.items()},
            "udp": {str(p): {"status": s, "info": i} for p, (s, i) in result.udp.items()},
        }
        print(json.dumps(out, indent=2))
    else:
        print_summary(result, args.target, color_enabled=not args.no_color)

    # final note
    print("Scan complete. For SYN-style scans, use Nmap (-sS) with proper authorization.")
    print("Plugins loaded:", [getattr(p, "name", p.__class__.__name__) for p in plugins])

if __name__ == "__main__":
    main()
