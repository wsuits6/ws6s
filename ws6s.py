#!/usr/bin/env python3
"""
Enhanced ws6s-scanner — improved, faster, cleaner and more extensible.
By Wsuits6 (Alhassan Osman Wunpini)
"""

import argparse
import socket
import time
import json
import sys
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

# ----------------------------
# Optional color support
# ----------------------------
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    GRAY = "\033[90m"
    RESET = "\033[0m"

def colorize(text, color, enable=True):
    return f"{color}{text}{Colors.RESET}" if enable else text

# ----------------------------
# Common service fingerprints
# ----------------------------
SERVICE_HINTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 123: "ntp",
    143: "imap", 161: "snmp", 443: "https",
    3306: "mysql", 3389: "rdp", 5900: "vnc",
    8080: "http-proxy"
}

# ----------------------------
# Port parsing
# ----------------------------
def parse_ports(port_str: str) -> List[int]:
    if not port_str:
        return list(range(1, 1001))

    ports = set()
    parts = port_str.split(",")

    for part in parts:
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                start, end = sorted((start, end))
                for p in range(start, end + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except:
                continue

    return sorted(ports)

# ----------------------------
# Banner grab logic
# ----------------------------
def grab_banner(sock) -> str:
    try:
        sock.settimeout(0.3)
        data = sock.recv(2048).decode(errors="ignore").strip()
        if not data:
            time.sleep(0.1)
            data = sock.recv(2048).decode(errors="ignore").strip()
        return data[:300]
    except:
        return ""

# ----------------------------
# Port scanner
# ----------------------------
def scan_port(target_ip: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target_ip, port))

        if result == 0:
            banner = grab_banner(s)
            s.close()

            hint = SERVICE_HINTS.get(port, "")
            if banner:
                hint = (hint + " | " + banner).strip() if hint else banner

            return port, True, hint
        else:
            s.close()
            return port, False, ""

    except Exception:
        return port, False, ""

# ----------------------------
# Main scanning orchestrator
# ----------------------------
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
        print("Error: Could not resolve host.")
        return

    try:
        rev = socket.gethostbyaddr(ip)[0]
    except:
        rev = None

    if not quiet:
        print(f"ws6s-scanner — target: {target} ({ip})")
        if rev:
            print(f"reverse DNS: {rev}")
        print(f"Scanning {len(ports)} ports with {threads} threads…")
        print("-" * 60)

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        for fut in as_completed(futures):
            port, is_open, hint = fut.result()

            if delay > 0:
                time.sleep(random.uniform(0, delay))

            if is_open:
                results.append((port, hint))

                if not quiet:
                    line = f"[OPEN] {port}/tcp"
                    if hint and verbose:
                        line += f" — {hint}"

                    print(colorize(line, Colors.GREEN, color))
            else:
                if verbose and not quiet:
                    print(colorize(f"[CLOSED] {port}/tcp", Colors.GRAY, color))

    elapsed = time.time() - start

    if json_output:
        output = {
            "target": target,
            "ip": ip,
            "open_ports": [{"port": p, "info": h} for p, h in results],
            "scan_time": elapsed,
        }
        print(json.dumps(output, indent=2))
        return

    print("-" * 60)
    if results:
        print("Open ports:")
        for p, h in results:
            line = f"  {p}/tcp"
            if h:
                line += f" — {h}"
            print(colorize(line, Colors.GREEN, color))
    else:
        print("No open ports found.")

    print(f"Scan completed in {elapsed:.2f}s.")

# ----------------------------
# Argument parser
# ----------------------------
def arg_builder():
    p = argparse.ArgumentParser(description="Enhanced ws6s TCP port scanner.")
    p.add_argument("target")
    p.add_argument("-p", "--ports", help="Port list or range. Default: 1-1000")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-T", "--threads", type=int, default=80)
    p.add_argument("-d", "--delay", type=float, default=0.0)
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--profile", choices=["fast", "stealth"], help="Preset scan profiles")
    return p

# ----------------------------
# Presets
# ----------------------------
def apply_profile(args):
    if args.profile == "fast":
        args.threads = 200
        args.timeout = 0.5
        args.delay = 0.0
    elif args.profile == "stealth":
        args.threads = 20
        args.timeout = 1.5
        args.delay = 0.05
    return args

# ----------------------------
# Entrypoint
# ----------------------------
def main():
    parser = arg_builder()
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
