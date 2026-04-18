# Network Security Audit Scripts

[![CI](https://github.com/ryantsou/network-security-audit-scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/ryantsou/network-security-audit-scripts/actions/workflows/ci.yml)

**Author:** Riantsoa RAJHONSON

Python scripts for common security audit tasks: host discovery, unused IP detection, and open port scanning.

## Overview

This repository contains three powerful security audit tools:

1. **detect_orphan_users.py** - Identifies orphan user accounts in Active Directory and Linux systems
2. **detect_unused_ips.py** - Scans network ranges to find unused/available IP addresses
3. **detect_open_ports.py** - Scans hosts for open ports and identifies potentially vulnerable services

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

Some scan modes require elevated privileges or optional Python packages.

## Usage

### Detect Orphan Users

```bash
# Scan Active Directory for orphan users
python detect_orphan_users.py -dc dc.example.com -u admin@example.com -p password

# Linux-only mode (no AD credentials required)
python detect_orphan_users.py -lh 192.168.1.10 192.168.1.11 -lu root -lp linuxpassword

python detect_orphan_users.py -dc dc.example.com -u admin@example.com -p password -o orphan_report.txt
```

### Detect Unused IPs

```bash
# Basic ping sweep
python detect_unused_ips.py -n 192.168.1.0/24 -m ping

# ARP scan (requires root/admin privileges)
python detect_unused_ips.py -n 192.168.1.0/24 -m arp

# Nmap scan
python detect_unused_ips.py -n 10.0.0.0/24 -m nmap -o unused_ips.txt

# Use all methods for comprehensive results
python detect_unused_ips.py -n 172.16.0.0/24 -m all -w 100
```

### Detect Open Ports

```bash
# Scan single host with default common ports
python detect_open_ports.py -t 192.168.1.1 -m socket

# Scan multiple hosts with specific ports
python detect_open_ports.py -t 192.168.1.1 192.168.1.2 -p 22,80,443,3389 -m scapy

# Comprehensive Nmap scan with service detection
python detect_open_ports.py -t 10.0.0.1 -m nmap -o scan_results.txt

# Scan all ports (warning: very slow!)
python detect_open_ports.py -t 192.168.1.1 --all-ports -m socket
```

## Command-Line Options

### detect_orphan_users.py

- `-dc, --domain-controller` - Domain controller address (required for AD scan)
- `-u, --username` - Domain admin username (required for AD scan)
- `-p, --password` - Domain admin password (required for AD scan)
- `-lh, --linux-hosts` - Linux hosts to check (space-separated)
- `-lu, --linux-user` - Linux SSH username (required with `-lh`)
- `-lp, --linux-password` - Linux SSH password (required with `-lh`)
- `-o, --output` - Output file for report

### detect_unused_ips.py

- `-n, --network` - Network range in CIDR notation (required)
- `-m, --method` - Scanning method: ping, arp, nmap, or all (default: ping)
- `-t, --timeout` - Timeout in seconds for each ping (default: 2)
- `-w, --workers` - Number of concurrent workers (default: 50)
- `-o, --output` - Output file for report

### detect_open_ports.py

- `-t, --targets` - Target host(s) to scan (required)
- `-p, --ports` - Ports to scan (comma-separated)
- `--all-ports` - Scan all ports 1-65535
- `-m, --method` - Scanning method: socket, scapy, or nmap (default: socket)
- `--timeout` - Timeout in seconds per connection (default: 2)
- `-o, --output` - Output file for report

## Security Considerations

⚠️ **Important Security Notes:**

- These tools are designed for legitimate security auditing purposes only
- Always obtain proper authorization before scanning networks or systems
- Some scanning methods may trigger IDS/IPS alerts
- Credential information should be handled securely
- Consider the impact on network performance during large scans
- Store reports securely as they may contain sensitive information
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
