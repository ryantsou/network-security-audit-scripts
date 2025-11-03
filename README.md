# Network Security Audit Scripts

**Author:** Riantsoa RAJHONSON

A comprehensive collection of Python security audit scripts designed to help network administrators and security professionals identify potential vulnerabilities and security issues in their infrastructure.

## Overview

This repository contains three powerful security audit tools:

1. **detect_orphan_users.py** - Identifies orphan user accounts in Active Directory and Linux systems
2. **detect_unused_ips.py** - Scans network ranges to find unused/available IP addresses
3. **detect_open_ports.py** - Scans hosts for open ports and identifies potentially vulnerable services

## Features

### Orphan User Detection
- Scans Active Directory for users without group memberships
- Checks Linux systems for users with missing home directories
- Generates detailed reports of orphan accounts
- Supports both Windows and Linux environments

### Unused IP Detection
- Multiple scanning methods: ping sweep, ARP scan, and Nmap
- Concurrent scanning for improved performance
- CIDR notation support for network ranges
- Identifies both active and unused IP addresses

### Open Port Scanning
- Three scanning methods: socket, Scapy, and Nmap
- Identifies risky ports automatically
- Service version detection (with Nmap)
- Concurrent scanning for faster results
- Comprehensive reporting with risk assessment

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

**Note:** Some features may require elevated privileges (root/administrator) to function properly, particularly ARP scanning and Scapy-based operations.

## Usage

### Detect Orphan Users

```bash
# Scan Active Directory for orphan users
python detect_orphan_users.py -dc dc.example.com -u admin@example.com -p password

# Include Linux hosts in the scan
python detect_orphan_users.py -dc dc.example.com -u admin@example.com -p password \
    -lh 192.168.1.10 192.168.1.11 -lu root -lp linuxpassword

# Save report to file
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

- `-dc, --domain-controller` - Domain controller address (required)
- `-u, --username` - Domain admin username (required)
- `-p, --password` - Domain admin password (required)
- `-lh, --linux-hosts` - Linux hosts to check (space-separated)
- `-lu, --linux-user` - Linux SSH username
- `-lp, --linux-password` - Linux SSH password
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

## Requirements

See `requirements.txt` for a complete list of dependencies:

- scapy>=2.5.0
- python-nmap>=0.7.1
- paramiko>=3.0.0
- pywinrm>=0.4.3
- ldap3>=2.9.1
- netaddr>=0.9.0
- ipaddress>=1.0.23
- argparse>=1.4.0

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Sedra Riantsoa Lala RAJHONSON**

## Disclaimer

These tools are provided "as is" without warranty of any kind. The author is not responsible for any damage or legal issues arising from the use of these scripts. Always ensure you have proper authorization before conducting security audits.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.

## Changelog

### Version 1.0.0 (Initial Release)
- Orphan user detection for AD and Linux
- Unused IP address detection with multiple methods
- Open port scanning with vulnerability assessment
- Comprehensive reporting capabilities
