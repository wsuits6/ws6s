# WS6S Enterprise Scanner v2.0

## Overview
An advanced, educational port scanner with TCP/UDP scanning capabilities, service fingerprinting, OS detection, plugin architecture, and an interactive curses-based UI.

**Author:** Alhassan Osman Wunpini (Wsuits6)

## ⚠️ Legal Disclaimer

**READ THIS CAREFULLY:**

This tool is for **educational purposes** and **authorized security testing only**. Unauthorized port scanning may be illegal in your jurisdiction and violate:

- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK  
- Local cybersecurity and hacking laws

**You MUST:**
- Have written permission before scanning any target
- Only scan systems you own or are authorized to test
- Follow all applicable laws and regulations
- Use responsibly and ethically

**The author assumes NO responsibility for misuse of this tool.**

## What's New in v2.0

### 🎯 Major Improvements

1. **Better Architecture**
   - Dataclass-based structures for clean code
   - Proper separation of concerns
   - Thread-safe operations
   - Comprehensive error handling

2. **Enhanced Service Detection**
   - Expanded service database (60+ services)
   - Better banner fingerprinting
   - Confidence levels (low/medium/high)
   - Protocol-specific UDP probes

3. **Improved OS Fingerprinting**
   - Port-based heuristics
   - Banner analysis
   - Multi-factor detection
   - Confidence indicators

4. **Plugin System Enhancements**
   - Better plugin discovery
   - Auto-generated example plugin
   - Error isolation
   - Post-scan hooks

5. **Professional UI**
   - Color-coded output
   - Real-time progress updates
   - Better curses interface
   - Keyboard navigation improvements

6. **Advanced Features**
   - Port presets (common, web, database)
   - Scan profiles (fast, normal, stealth)
   - Result saving (JSON/TXT)
   - Comprehensive statistics
   - Better logging

## Installation

### Requirements

```bash
# Python 3.7+
python3 --version

# No external dependencies - uses standard library only!
```

### Setup

```bash
# Make executable
chmod +x ws6s_scanner_v2.py

# Create alias (optional)
echo 'alias ws6s="/path/to/ws6s_scanner_v2.py"' >> ~/.bashrc
source ~/.bashrc
```

## Quick Start

```bash
# Basic scan
./ws6s_scanner_v2.py example.com

# Scan specific ports
./ws6s_scanner_v2.py -p 22,80,443 example.com

# Scan common ports with verbose output
./ws6s_scanner_v2.py -p common -v example.com

# Fast scan with interactive UI
./ws6s_scanner_v2.py --profile fast --curses example.com

# Full scan with UDP and plugins
./ws6s_scanner_v2.py -p 1-1000 --udp --plugins --save json example.com
```

## Usage Guide

### Basic Syntax

```
ws6s_scanner_v2.py [OPTIONS] TARGET
```

### Port Specification

```bash
# Single port
-p 80

# Multiple ports
-p 22,80,443

# Port ranges
-p 1-1024
-p 80-100,443,8000-8100

# Mixed
-p 22,80-100,443,3000-4000

# Presets
-p common      # Top 20 common ports
-p web         # Web ports (80, 443, 8080, etc.)
-p database    # Database ports (3306, 5432, etc.)
-p all         # All 65535 ports (very slow!)
```

### Scan Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-t, --timeout` | Connection timeout (seconds) | 1.0 | `-t 2.0` |
| `-T, --threads` | Number of worker threads | 200 | `-T 500` |
| `--udp` | Enable UDP scanning | False | `--udp` |
| `--tcp-only` | TCP scanning only | True | `--tcp-only` |
| `--profile` | Scan profile (fast/normal/stealth) | normal | `--profile fast` |

### Scan Profiles

**Fast Profile:**
- Fewer threads (max 100)
- Short timeout (0.5s)
- Best for: Quick reconnaissance

**Normal Profile (Default):**
- Balanced settings
- Medium timeout (1.0s)
- Best for: General scanning

**Stealth Profile:**
- Fewer threads (max 50)
- Longer timeout (2.0s)
- Best for: Avoiding detection

### Output Options

```bash
# JSON output to console
--json

# Save to file
--save json     # Save as JSON
--save txt      # Save as text report

# Interactive UI
--curses        # Launch curses interface after scan

# Disable colors
--no-color

# Verbose output
-v, --verbose
```

### Plugin System

```bash
# Enable plugins
--plugins

# Plugins are loaded from ./plugins/ directory
# Example: ./plugins/plugin_example.py
```

## Examples

### Example 1: Quick Common Port Scan
```bash
./ws6s_scanner_v2.py -p common example.com
```

### Example 2: Web Application Scan
```bash
./ws6s_scanner_v2.py -p web --verbose example.com
```

### Example 3: Database Server Audit
```bash
./ws6s_scanner_v2.py -p database -T 100 database.example.com
```

### Example 4: Comprehensive Scan with Reporting
```bash
./ws6s_scanner_v2.py -p 1-1000 --udp --plugins --save json --curses example.com
```

### Example 5: Stealth Scan
```bash
./ws6s_scanner_v2.py -p 1-1024 --profile stealth example.com
```

### Example 6: Fast Internal Network Scan
```bash
./ws6s_scanner_v2.py -p 1-10000 --profile fast --threads 500 192.168.1.1
```

## Interactive UI

When launched with `--curses`, the scanner provides an interactive interface:

### Controls
- **↑/↓** - Navigate through ports
- **Page Up/Down** - Scroll by page
- **Home/End** - Jump to start/end
- **o** - Filter: Open ports only
- **a** - Filter: All ports
- **t** - Filter: TCP ports only
- **u** - Filter: UDP ports only
- **q** - Quit

### Display
- Color-coded status (green=open, red=closed, yellow=filtered)
- Real-time statistics
- Port details (protocol, status, service, banner)
- OS detection hint

## Plugin Development

### Plugin Structure

Plugins are Python files in the `plugins/` directory named `plugin_*.py`.

Example plugin:

```python
"""
Custom service detection plugin
"""
from typing import Optional

class Plugin:
    name = "custom_detector"
    
    def probe_tcp(self, ip: str, port: int, banner: str) -> Optional[str]:
        """
        Analyze TCP banner for custom services.
        
        Args:
            ip: Target IP
            port: Port number
            banner: Grabbed banner string
            
        Returns:
            Additional service info or None
        """
        if "MyCustomService" in banner:
            return "MyCustomService Detected v1.0"
        return None
    
    def probe_udp(self, ip: str, port: int) -> Optional[str]:
        """
        Perform custom UDP probing.
        
        Args:
            ip: Target IP
            port: Port number
            
        Returns:
            Service info or None
        """
        # Send custom probe and analyze response
        return None
    
    def post_scan(self, result) -> None:
        """
        Process complete scan results.
        
        Args:
            result: ScanResult object
        """
        open_ports = result.get_open_ports()
        print(f"[{self.name}] Detected {len(open_ports)} open ports")
        
        # Generate custom report, send alerts, etc.
```

### Plugin Methods

**probe_tcp(ip, port, banner) -> Optional[str]**
- Called for each open TCP port
- Receives the grabbed banner
- Can return additional service information

**probe_udp(ip, port) -> Optional[str]**
- Called for each UDP port probe
- Can send custom UDP packets
- Returns service detection info

**post_scan(result) -> None**
- Called after scan completes
- Receives complete ScanResult object
- Can generate reports, send notifications, etc.

## Service Detection

### Built-in Service Database

The scanner includes fingerprints for 60+ services:

**Network Services:**
- FTP (20, 21, 990)
- SSH (22)
- Telnet (23)
- DNS (53)
- DHCP (67, 68)
- TFTP (69)

**Web Services:**
- HTTP (80, 8000, 8080, 8888, 9000)
- HTTPS (443, 8443)

**Mail Services:**
- SMTP (25, 465, 587)
- POP3 (110, 995)
- IMAP (143, 993)

**Databases:**
- MySQL (3306)
- PostgreSQL (5432)
- MSSQL (1433)
- Oracle (1521)
- MongoDB (27017)
- Redis (6379)
- Elasticsearch (9200)

**And many more...**

### Banner Fingerprinting

The scanner matches banners against known patterns:
- OpenSSH, Dropbear → SSH
- Apache, nginx, IIS → Web servers
- vsftpd, ProFTPD → FTP servers
- MySQL, PostgreSQL, MongoDB → Databases

## OS Detection

The scanner attempts to identify the target OS using:

1. **Open port patterns:**
   - Windows: 135, 139, 445, 3389
   - Linux: 22, 111, 2049

2. **Banner analysis:**
   - Searches for OS names in banners
   - Checks for OS-specific software

3. **Confidence levels:**
   - Results marked as "heuristic" or "likely"
   - Not as accurate as nmap's OS detection

## Output Formats

### Console Output

```
======================================================================
 WS6S ENTERPRISE SCANNER - Scan Results 
======================================================================

Target:   example.com (93.184.216.34)
Started:  2026-01-28 14:30:45
Duration: 12.45s
Scanned:  1024 ports (TCP: 1024, UDP: 0)
Open:     3
OS Hint:  Linux (Apache/2.4.41 banner hint)

TCP Ports (Open):
Port    Service                   Confidence   Banner
----------------------------------------------------------------------
     22 ssh                       high         SSH-2.0-OpenSSH_8.2p1 Ubuntu
     80 http | Apache            high         Apache/2.4.41 (Ubuntu)
    443 https                     medium       

======================================================================
```

### JSON Output

```json
{
  "target": "example.com",
  "ip": "93.184.216.34",
  "timestamp": "2026-01-28T14:30:45",
  "duration": 12.45,
  "os_hint": "Linux (Apache/2.4.41 banner hint)",
  "statistics": {
    "total_scanned": 1024,
    "tcp_scanned": 1024,
    "udp_scanned": 0,
    "open_ports": 3,
    "duration": 12.45
  },
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "status": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu",
      "confidence": "high"
    }
  ]
}
```

## Performance Tuning

### Thread Count

```bash
# Low threads (stealth)
-T 50

# Medium threads (balanced)
-T 200  # Default

# High threads (fast, local network)
-T 500

# Very high threads (very fast, may overwhelm target)
-T 1000
```

### Timeout Settings

```bash
# Fast scan (may miss slow services)
-t 0.5

# Normal (balanced)
-t 1.0  # Default

# Patient (catches slow services)
-t 2.0

# Very patient (comprehensive)
-t 5.0
```

### Optimization Tips

1. **Local Network:** Use higher threads (500+) and shorter timeout (0.5s)
2. **Internet Hosts:** Use moderate threads (100-200) and normal timeout (1.0s)
3. **Slow Targets:** Use fewer threads (50) and longer timeout (2.0s+)
4. **Stealth:** Use profile `--profile stealth`

## Comparison: v1.0 vs v2.0

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Service Database | 20+ | 60+ |
| Code Structure | Monolithic | Modular/Dataclasses |
| Error Handling | Basic | Comprehensive |
| Port Presets | No | Yes (common/web/db) |
| Scan Profiles | Yes | Enhanced (fast/normal/stealth) |
| Progress Display | Limited | Real-time with colors |
| Result Saving | JSON only | JSON + TXT |
| Plugin System | Basic | Enhanced with templates |
| OS Detection | Basic | Improved heuristics |
| UDP Probes | Generic | Protocol-specific |
| UI | Basic curses | Enhanced with filtering |
| Logging | Print statements | Proper logging module |
| Documentation | Minimal | Comprehensive |

## Troubleshooting

### Issue: "Permission denied"
```bash
# Make script executable
chmod +x ws6s_scanner_v2.py
```

### Issue: "Could not resolve hostname"
```bash
# Check DNS
nslookup example.com

# Try IP address directly
./ws6s_scanner_v2.py 93.184.216.34
```

### Issue: "Too many open files"
```bash
# Increase file descriptor limit
ulimit -n 4096

# Or reduce threads
./ws6s_scanner_v2.py -T 100 example.com
```

### Issue: Scan is very slow
```bash
# Use fast profile
./ws6s_scanner_v2.py --profile fast example.com

# Reduce port range
./ws6s_scanner_v2.py -p common example.com

# Increase threads
./ws6s_scanner_v2.py -T 500 example.com
```

### Issue: No ports detected as open
- Target may have firewall
- Try longer timeout: `-t 3.0`
- Check if target is reachable: `ping example.com`
- Verify ports are actually open: `nc -zv example.com 80`

### Issue: Curses UI doesn't work
```bash
# Check terminal supports curses
echo $TERM  # Should show xterm or similar

# Try without curses
./ws6s_scanner_v2.py example.com

# Use tmux or screen
tmux
./ws6s_scanner_v2.py --curses example.com
```

## Limitations

1. **Not a replacement for nmap:** This is educational. For professional use, use nmap.

2. **No SYN scanning:** Requires raw sockets/root. Use nmap -sS for stealth scans.

3. **UDP unreliability:** UDP scanning is inherently unreliable. Lack of response doesn't mean closed.

4. **OS detection accuracy:** Heuristic-based, not as accurate as nmap's -O option.

5. **No evasion techniques:** Doesn't implement IDS evasion, fragmentation, etc.

6. **Banner grabbing limits:** Some services don't send banners or need specific probes.

## Best Practices

### Before Scanning

- [ ] Get written authorization
- [ ] Understand the scope
- [ ] Know the legal implications
- [ ] Have incident response plan
- [ ] Schedule scanning windows

### During Scanning

- [ ] Start with fast/common ports
- [ ] Monitor for blocking
- [ ] Respect rate limits
- [ ] Document all activities
- [ ] Save results for evidence

### After Scanning

- [ ] Analyze results carefully
- [ ] Validate findings manually
- [ ] Report responsibly
- [ ] Archive scan data
- [ ] Follow disclosure timelines

## Security Considerations

### Stealth

This scanner:
- ✅ Uses TCP connect (not SYN stealth)
- ✅ Can be detected by firewalls/IDS
- ✅ Leaves logs on target systems
- ✅ May trigger alerts

For stealthy scanning:
- Use `nmap -sS` (requires root)
- Implement timing controls
- Use decoy IPs
- Fragment packets

### Detection Avoidance

```bash
# Slow down scan
--profile stealth -T 20 -t 3

# Randomize ports (not implemented)
# Use nmap --randomize-hosts

# Space out packets (not implemented)
# Use nmap --scan-delay
```

## Integration Examples

### With Other Tools

```bash
# Feed results to other scanners
./ws6s_scanner_v2.py -p common example.com --save json
cat scan_results/scan_example_com_*.json | jq -r '.ports[] | select(.status=="open") | .port'

# Pipe to nmap for service version detection
./ws6s_scanner_v2.py -p 1-1000 example.com --json | \
  jq -r '.ports[] | select(.status=="open") | .port' | \
  tr '\n' ',' | sed 's/,$//' | \
  xargs -I {} nmap -sV -p {} example.com
```

### Automation

```bash
# Scan multiple targets
for target in $(cat targets.txt); do
    ./ws6s_scanner_v2.py -p common --save json "$target"
done

# Cron job
0 2 * * * /path/to/ws6s_scanner_v2.py -p common --save json example.com
```

## FAQ

**Q: Why not include SYN scanning?**
A: SYN scanning requires raw sockets and root privileges. It's also more detectable from a legal standpoint. Use nmap -sS for that.

**Q: Is this better than nmap?**
A: No. This is educational. Nmap is the industry standard and far more capable.

**Q: Can I use this in production?**
A: Only with proper authorization and in controlled environments. For production security assessments, use professional tools like nmap, masscan, or commercial scanners.

**Q: Why is UDP scanning so slow/unreliable?**
A: UDP is connectionless. We can't tell if a port is open without a response. Many services don't respond to probes. This is a fundamental limitation of UDP.

**Q: How can I make it faster?**
A: Use --profile fast, increase threads (-T 500), reduce timeout (-t 0.5), scan fewer ports (-p common).

**Q: Can it bypass firewalls?**
A: No. This is a straightforward scanner. For firewall evasion, use nmap's advanced features (-f, --mtu, decoys, etc.).

## Support

For issues or questions:
1. Read this documentation
2. Check the troubleshooting section
3. Review the code comments
4. Test with a known-open port (e.g., your own server)

## Credits

- **Original Author:** Alhassan Osman Wunpini (Wsuits6)
- **Inspired by:** nmap, masscan, and other security tools
- **Built with:** Python 3 standard library only

## License

Educational use only. See legal disclaimer at the top of this document.

---

**Remember: Always get authorization before scanning. Stay legal. Stay ethical.**

**For professional scanning, use:**
- nmap: https://nmap.org
- masscan: https://github.com/robertdavidgraham/masscan
- rustscan: https://github.com/RustScan/RustScan