# Network Security Audit Scripts

[![CI](https://github.com/ryantsou/network-security-audit-scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/ryantsou/network-security-audit-scripts/actions/workflows/ci.yml)

**Author:** Riantsoa RAJHONSON

Python scripts for common security audit tasks: host discovery, unused IP detection, and open port scanning.

## Project Status

This project provides:
- Improved input validation and safer CLI behavior
- Better resilience when optional dependencies are not installed
- Unit tests for critical logic and CLI flows
- Automated CI validation on push and pull requests
- Updated documentation aligned with current script behavior

## Highlights

- Lightweight Python tooling for common security audit tasks
- Modular scanning modes with optional dependencies
- CLI-first workflow with report generation
- Unit-tested core logic
- GitHub Actions CI for repeatable validation

## Continuous Integration (CI)

GitHub Actions workflow file:
- `.github/workflows/ci.yml`

It automatically runs on each push and pull request:
- Dependency installation from `requirements.txt`
- Syntax validation for all audit scripts
- Unit tests from `tests/`

The badge points to the repository CI workflow for this project.

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

Dependency behavior:
- `scapy` is required only for `scapy`/ARP-based scan modes
- `python-nmap` is required only for `nmap` scan modes
- `ldap3` is required for Active Directory orphan user detection
- `paramiko` is required for Linux orphan user checks over SSH

## Usage

### Detect Orphan Users

```bash
# Scan Active Directory for orphan users
python detect_orphan_users.py -dc dc.example.com -u admin@example.com -p password

# Linux-only mode (no AD credentials required)
python detect_orphan_users.py -lh 192.168.1.10 192.168.1.11 -lu root -lp linuxpassword

# Include Linux hosts in the scan
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

You can run AD-only, Linux-only, or both in one execution.

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

Input validation:
- Invalid port values outside `1-65535` are rejected with a clear error message.

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
- ldap3>=2.9.1

## Tests

Run the unit test suite:

```bash
python -m unittest discover -s tests -v
```

Run a quick syntax validation:

```bash
python -m py_compile detect_open_ports.py detect_orphan_users.py detect_unused_ips.py
```

The test suite validates core parsing, report generation, command building, and CLI validation flows without requiring real network scanning.

Current local validation status:
- Unit tests: `10 passed`
- Syntax check: `OK`

## Suggested Improvements

Potential next steps for a stronger release:
- Add JSON and CSV export formats for machine-readable reporting
- Add a single orchestration command to discover live hosts and scan ports in one workflow
- Add IPv6 support for discovery and port scanning
- Add severity scoring and summary statistics to reports
- Add banner output and `--quiet` / `--verbose` flags for better operator control
- Add optional host discovery via ARP/Nmap as a first-class mode in the port scanner

## Demo

For public sharing, use anonymized demo data and keep real LAN reports private.

Example demo commands:

```bash
# Discovery demo using a documentation-only subnet
python detect_unused_ips.py -n 192.0.2.0/30 -m ping -t 1 -w 10 -o demo_unused_ips.txt

# Port scan demo against placeholder targets
python detect_open_ports.py -t 192.0.2.10 192.0.2.11 -p 22,80,443 --timeout 1 -m socket -o demo_open_ports.txt
```

Public demo rules:
- Do not publish real LAN IPs, hostnames, or credentials
- Keep real scan reports local and out of version control
- Use the generated demo files only as illustrative artifacts

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Sedra Riantsoa Lala RAJHONSON**

## Disclaimer

These tools are provided "as is" without warranty of any kind. The author is not responsible for any damage or legal issues arising from the use of these scripts. Always ensure you have proper authorization before conducting security audits.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.

## Changelog

### Version 1.1.0
- Added automated unit tests in `tests/`
- Made optional dependencies lazy-loaded to avoid blocking unrelated scan modes
- Improved CLI validation for AD-only, Linux-only, and combined orphan-user workflows
- Added stricter port input validation for open port scanning
- Updated README and requirements for consistency

### Version 1.0.0 (Initial Release)
- Orphan user detection for AD and Linux
- Unused IP address detection with multiple methods
- Open port scanning with vulnerability assessment
- Comprehensive reporting capabilities
