#!/usr/bin/env python3
"""
=========================
By Alhassan Osman Wunpini
wsuits6@gmail.com
=========================
"""

"""
ws6s_scanner.py — a small, user-friendly TCP port scanner for terminal use.

Author: Wsuits6 (suggested)
Features:
 - Default: scans first 1000 TCP ports (1-1000) if --ports isn't provided.
 - Accepts single ports, comma-separated lists, and ranges (e.g. 1-1024).
 - Uses socket.connect_ex (no root required).
 - Optional threading for speed (conservative defaults).
 - Optional small random delay between probes to be gentle.
 - Simple service name hints for common ports.
 - Clean, well-commented, extendable codebase.
 
WARNING: Only use against hosts you own or have explicit permission to test.
"""

import argparse
import socket
import time
import os
import sys
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

# ---------------------------
# Simple common services map
# ---------------------------
COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    123: "ntp", 143: "imap", 161: "snmp", 194: "irc", 443: "https",
    445: "microsoft-ds", 3306: "mysql", 3389: "ms-wbt-server", 5900: "vnc",
    8080: "http-proxy"
}

# ---------------------------
# Utility: parse ports string
# ---------------------------
def parse_ports(ports_str: str) -> List[int]:
    """
    Parse a ports string like:
      - None or "" => default first 1000 ports -> 1..1000
      - "80" => [80]
      - "22,80,443" => [22,80,443]
      - "1-1024" => [1..1024]
      - combined => "22,80,1000-1010"
    Returns sorted unique list of ints.
    """
    if not ports_str:
        return list(range(1, 1001))  # default first 1000 ports
    ports = set()
    parts = ports_str.split(",")
    for p in parts:
        p = p.strip()
        if "-" in p:
            try:
                start, end = p.split("-", 1)
                start_i = int(start)
                end_i = int(end)
                if start_i > end_i:
                    start_i, end_i = end_i, start_i
                for x in range(max(1, start_i), min(65535, end_i) + 1):
                    ports.add(x)
            except ValueError:
                continue
        else:
            try:
                pi = int(p)
                if 1 <= pi <= 65535:
                    ports.add(pi)
            except ValueError:
                continue
    return sorted(ports)

# ---------------------------
# Single-port scanner
# ---------------------------
def scan_port(target: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    """
    Attempt a TCP connect to (target, port). Return (port, is_open, banner_hint).
    Uses socket.connect_ex which returns 0 on success.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                # Optionally try to read a small banner (non-blocking, may not exist)
                banner = ""
                try:
                    s.settimeout(0.5)
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
                hint = COMMON_SERVICES.get(port, "")
                if banner:
                    # keep banner short
                    banner = banner.replace("\r", " ").replace("\n", " ")
                    if len(banner) > 200:
                        banner = banner[:200] + "..."
                    hint = f"{hint} | banner: {banner}" if hint else f"banner: {banner}"
                return (port, True, hint)
            else:
                return (port, False, "")
    except socket.gaierror:
        # Hostname resolution issue
        raise
    except Exception:
        return (port, False, "")

# ---------------------------
# Main scanning routine
# ---------------------------
def run_scan(target: str, ports: List[int], timeout: float, threads: int, max_delay: float, verbose: bool):
    """
    Orchestrate port scanning with optional thread pool.
    max_delay: random max delay (seconds) between tasks to be gentle/stealthy-minded.
    """
    start_time = time.time()

    # Resolve target to IP, also get reverse DNS if available
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        return

    try:
        rev = socket.gethostbyaddr(ip)[0]
    except Exception:
        rev = None

    print(f"ws6s-scanner — target: {target} ({ip})")
    if rev:
        print(f"reverse DNS: {rev}")
    print(f"ports to scan: {len(ports)} (threads: {threads}, timeout: {timeout}s, max_delay: {max_delay}s)")
    print("-" * 60)

    open_ports = []

    # Threaded scan
    with ThreadPoolExecutor(max_workers=threads) as exe:
        # Submit futures
        futures = {}
        for port in ports:
            # gentle random delay before scheduling if requested
            if max_delay and max_delay > 0:
                # small sleep here is intentionally short; we also use a per-task delay below
                time.sleep(random.uniform(0, min(0.002, max_delay)))
            futures[exe.submit(scan_port, ip, port, timeout)] = port

        # Process results as they complete
        for fut in as_completed(futures):
            try:
                port, is_open, hint = fut.result()
            except Exception as e:
                # If hostname resolution failed mid-scan, break
                print(f"[!] Error scanning: {e}")
                continue

            # small randomized polite delay between printing/results to avoid flooding logs
            if max_delay and max_delay > 0:
                time.sleep(random.uniform(0, max_delay))

            if is_open:
                open_ports.append((port, hint))
                if verbose:
                    print(f"[+] {port:5d}/tcp OPEN    {hint}")
                else:
                    # concise
                    service_hint = f" ({hint})" if hint else ""
                    print(f"[+] {port:5d}/tcp OPEN{service_hint}")

    elapsed = time.time() - start_time
    print("-" * 60)
    if open_ports:
        print(f"Open ports ({len(open_ports)}):")
        for p, hint in sorted(open_ports):
            hint_text = f" — {hint}" if hint else ""
            print(f"  {p:5d}/tcp{hint_text}")
    else:
        print("No open ports found (with current settings).")
    print(f"Scan completed in {elapsed:.2f} seconds.")

# ---------------------------
# CLI: argument parsing
# ---------------------------
def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="ws6s-scanner",
        description="Simple, friendly TCP port scanner (default: first 1000 ports). "
                    "Only scan hosts you have permission to test."
    )
    p.add_argument("target", help="Target hostname or IP (e.g. example.com or 192.168.1.1)")
    p.add_argument(
        "-p", "--ports", default=None,
        help="Ports to scan. Examples: '80', '22,80,443', '1-1024'. Default: 1-1000"
    )
    p.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds for each probe (default: 1.0)"
    )
    p.add_argument(
        "-T", "--threads", type=int, default=50,
        help="Number of worker threads (default: 50). Lower for stealth, higher for speed."
    )
    p.add_argument(
        "-d", "--max-delay", type=float, default=0.01,
        help="Max random delay (seconds) between probes to be polite/stealthy (default 0.01). Set 0 for no delay."
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output (show banner hints inline)."
    )
    p.add_argument(
        "--no-color", action="store_true",
        help=argparse.SUPPRESS  # placeholder if you want to add color later
    )
    return p

# ---------------------------
# Entrypoint
# ---------------------------
def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # Quick authorization reminder — printed but does not block
    print("=== ws6s-scanner ===")
    print("Reminder: only scan machines you own or have explicit permission to test.\n")

    # Parse ports list
    ports = parse_ports(args.ports)

    # Normalize target
    target = args.target.strip()

    try:
        run_scan(target, ports, timeout=args.timeout, threads=max(1, args.threads),
                 max_delay=max(0.0, args.max_delay), verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
