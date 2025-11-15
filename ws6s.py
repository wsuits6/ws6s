#!/usr/bin/env python3
"""
====================================================================
                          WS6S PORT SCANNER
                  Advanced, Fast, Extensible TCP Scanner
                     By Alhassan Osman Wunpini (Wsuits6)
====================================================================

Features:
 - TCP connect scanning (no raw sockets required)
 - Optional JSON output
 - Banner grabbing with fingerprint hints
 - Multi-threaded scanning engine
 - Custom scan profiles (fast, stealth, normal)
 - Color output (optional)
 - Quiet mode, verbose mode
 - Resolves DNS + reverse DNS
 - Clean modular design for future UDP/SYN/OS modules

Use responsibly. Only scan systems you are authorized to test.
====================================================================
"""

import argparse
import socket
import time
import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

# ------------------------------------------------------------
# Color utilities
# ------------------------------------------------------------
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

def colorize(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{Colors.RESET}" if enabled else text

# ------------------------------------------------------------
# Known services (expandable)
# ------------------------------------------------------------
SERVICE_HINTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    123: "ntp", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 514: "shell", 587: "smtp-sub",
    631: "ipp", 902: "vmware-auth", 1080: "socks",
    1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 9000: "php-fpm", 9200: "elasticsearch"
}

# ------------------------------------------------------------
# Port list parser
# ------------------------------------------------------------
def parse_ports(port_str: str) -> List[int]:
    if not port_str:
        return list(range(1, 1001))  # default

    ports = set()
    chunks = port_str.split(",")

    for c in chunks:
        c = c.strip()
        if "-" in c:
            try:
                start, end = map(int, c.split("-"))
                if start > end:
                    start, end = end, start
                for p in range(start, end + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except:
                continue
        else:
            try:
                p = int(c)
                if 1 <= p <= 65535:
                    ports.add(p)
            except:
                continue
    return sorted(ports)

# ------------------------------------------------------------
# Banner grabber
# ------------------------------------------------------------
def grab_banner(sock) -> str:
    try:
        sock.settimeout(0.3)
        data = sock.recv(2048).decode(errors="ignore").strip()
        return data[:300]
    except:
        return ""

# ------------------------------------------------------------
# Single port scan
# ------------------------------------------------------------
def scan_port(ip: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))

        if result == 0:
            banner = grab_banner(s)
            s.close()

            service = SERVICE_HINTS.get(port, "")
            if banner:
                service = f"{service} | {banner}" if service else banner

            return port, True, service

        s.close()
        return port, False, ""

    except Exception:
        return port, False, ""

# ------------------------------------------------------------
# Main scanning engine
# ------------------------------------------------------------
def run_scan(target: str,
             ports: List[int],
             timeout: float,
             threads: int,
             delay: float,
             verbose: bool,
             quiet: bool,
             json_output: bool,
             color: bool):

    start = time.time()

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Unable to resolve target.")
        sys.exit(1)

    try:
        rev = socket.gethostbyaddr(ip)[0]
    except:
        rev = None

    if not quiet:
        print(colorize("====================================================================", Colors.CYAN, color))
        print(colorize("                           WS6S PORT SCANNER", Colors.YELLOW, color))
        print(colorize("====================================================================", Colors.CYAN, color))
        print(f"Target       : {target} ({ip})")
        print(f"Reverse DNS  : {rev if rev else 'None'}")
        print(f"Ports        : {len(ports)}")
        print(f"Threads      : {threads}")
        print(f"Timeout      : {timeout}s")
        print("--------------------------------------------------------------------")

    open_results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}

        for fut in as_completed(futures):
            port, opened, info = fut.result()

            if delay > 0:
                time.sleep(random.uniform(0, delay))

            if opened:
                open_results.append((port, info))

                if not quiet:
                    msg = f"[OPEN] {port}/tcp"
                    if info and verbose:
                        msg += f"  ->  {info}"
                    print(colorize(msg, Colors.GREEN, color))
            else:
                if verbose and not quiet:
                    print(colorize(f"[CLOSED] {port}/tcp", Colors.RED, color))

    elapsed = time.time() - start

    if json_output:
        out = {
            "target": target,
            "ip": ip,
            "open_ports": [{"port": p, "info": i} for p, i in open_results],
            "time_seconds": elapsed
        }
        print(json.dumps(out, indent=2))
        return

    print("--------------------------------------------------------------------")
    if open_results:
        print("Open Ports:")
        for p, info in open_results:
            line = f"  {p}/tcp"
            if info:
                line += f"  ->  {info}"
            print(colorize(line, Colors.GREEN, color))
    else:
        print("No open ports detected.")

    print(f"Completed in {elapsed:.2f} seconds.")
    print("====================================================================")

# ------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------
def build_args():
    p = argparse.ArgumentParser(description="WS6S High-Performance Port Scanner.")
    p.add_argument("target")
    p.add_argument("-p", "--ports", help="Examples: 80,22,1-1024")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-T", "--threads", type=int, default=120)
    p.add_argument("-d", "--delay", type=float, default=0.0)
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--profile", choices=["fast", "stealth", "normal"])
    return p

# ------------------------------------------------------------
# Scan profiles
# ------------------------------------------------------------
def apply_profile(args):
    if args.profile == "fast":
        args.threads = 300
        args.timeout = 0.4
        args.delay = 0
    elif args.profile == "stealth":
        args.threads = 20
        args.timeout = 1.5
        args.delay = 0.05
    elif args.profile == "normal":
        args.threads = 100
        args.timeout = 1.0
        args.delay = 0
    return args

# ------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------
def main():
    parser = build_args()
    args = parser.parse_args()
    args = apply_profile(args)

    ports = parse_ports(args.ports)

    run_scan(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        delay=args.delay,
        verbose=args.verbose,
        quiet=args.quiet,
        json_output=args.json,
        color=not args.no_color
    )

if __name__ == "__main__":
    main()
