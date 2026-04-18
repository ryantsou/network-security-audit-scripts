#!/usr/bin/env python3
"""
Unused IP Detection Script
Author: Riantsoa RAJHONSON
Description: Scans network ranges to identify unused/available IP addresses
"""

import argparse
import sys
import ipaddress
import subprocess
import platform
import concurrent.futures
from datetime import datetime


class UnusedIPDetector:
    def __init__(self, network_range, timeout=2):
        self.network_range = network_range
        self.timeout = timeout
        self.used_ips = set()
        self.unused_ips = set()
        self.all_ips = []
        self._scapy_available = None
        self._nmap_available = None
        self._scapy_import_error = None
        self._nmap_import_error = None
        
    def validate_network(self):
        """Validate network CIDR notation"""
        try:
            network = ipaddress.ip_network(self.network_range, strict=False)
            self.all_ips = [str(ip) for ip in network.hosts()]
            print(f"[*] Scanning network: {network}")
            print(f"[*] Total IPs to scan: {len(self.all_ips)}")
            return True
        except ValueError as e:
            print(f"Error: Invalid network range - {e}")
            return False
    
    def ping_sweep(self, ip):
        """Perform ping sweep to detect active hosts"""
        command = self._build_ping_command(ip)
        
        try:
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=self.timeout)
            if result.returncode == 0:
                return ip, True
            return ip, False
        except subprocess.TimeoutExpired:
            return ip, False
        except Exception:
            return ip, False

    def _build_ping_command(self, ip):
        """Build a cross-platform ping command with a single probe and timeout."""
        os_name = platform.system().lower()
        if os_name == 'windows':
            timeout_ms = int(self.timeout * 1000)
            return ['ping', '-n', '1', '-w', str(timeout_ms), ip]
        timeout_seconds = max(1, int(round(self.timeout)))
        return ['ping', '-c', '1', '-W', str(timeout_seconds), ip]

    def _ensure_scapy(self):
        """Lazy import Scapy so ping/nmap can run without it."""
        if self._scapy_available is not None:
            return self._scapy_available
        try:
            from scapy.all import ARP, Ether, srp
            self._ARP = ARP
            self._Ether = Ether
            self._srp = srp
            self._scapy_available = True
        except ImportError as e:
            self._scapy_import_error = str(e)
            self._scapy_available = False
        return self._scapy_available

    def _ensure_nmap(self):
        """Lazy import python-nmap so ping/arp can run without it."""
        if self._nmap_available is not None:
            return self._nmap_available
        try:
            import nmap
            self._nmap = nmap
            self._nmap_available = True
        except ImportError as e:
            self._nmap_import_error = str(e)
            self._nmap_available = False
        return self._nmap_available
    
    def arp_scan(self):
        """Use ARP scanning for more reliable detection (requires root/admin)"""
        print("[*] Performing ARP scan (may require elevated privileges)...")
        if not self._ensure_scapy():
            print(f"[!] Scapy module unavailable: {self._scapy_import_error}")
            return False
        try:
            # Create ARP packet
            arp = self._ARP(pdst=self.network_range)
            ether = self._Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and capture response
            result = self._srp(packet, timeout=self.timeout, verbose=False)[0]
            
            for sent, received in result:
                self.used_ips.add(received.psrc)
                print(f"[+] Found active IP: {received.psrc} (MAC: {received.hwsrc})")
            
            return True
        except PermissionError:
            print("[!] ARP scan requires root/administrator privileges")
            return False
        except Exception as e:
            print(f"[!] ARP scan failed: {e}")
            return False
    
    def nmap_scan(self):
        """Use nmap for comprehensive scanning"""
        print("[*] Performing Nmap scan...")
        if not self._ensure_nmap():
            print(f"[!] Nmap module unavailable: {self._nmap_import_error}")
            return False
        try:
            nm = self._nmap.PortScanner()
            nm.scan(hosts=self.network_range, arguments='-sn')  # Ping scan only
            
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    self.used_ips.add(host)
                    print(f"[+] Found active IP: {host}")
            
            return True
        except Exception as e:
            print(f"[!] Nmap scan failed: {e}")
            return False
    
    def concurrent_ping_sweep(self, max_workers=50):
        """Perform concurrent ping sweep for faster scanning"""
        print(f"[*] Starting concurrent ping sweep with {max_workers} workers...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.ping_sweep, ip): ip for ip in self.all_ips}
            
            completed = 0
            total = len(self.all_ips)
            
            for future in concurrent.futures.as_completed(future_to_ip):
                try:
                    ip, is_active = future.result()
                except Exception as e:
                    print(f"[!] Ping worker failed: {e}")
                    continue
                completed += 1
                
                if is_active:
                    self.used_ips.add(ip)
                    print(f"[+] Found active IP: {ip} ({completed}/{total})")
                else:
                    if completed % 50 == 0:  # Progress update every 50 IPs
                        print(f"[*] Progress: {completed}/{total} IPs scanned")
    
    def identify_unused_ips(self):
        """Identify unused IPs by comparing all IPs with used IPs"""
        all_ip_set = set(self.all_ips)
        self.unused_ips = all_ip_set - self.used_ips
        
        print(f"\n[*] Scan completed!")
        print(f"[*] Total IPs scanned: {len(all_ip_set)}")
        print(f"[*] Active IPs found: {len(self.used_ips)}")
        print(f"[*] Unused IPs found: {len(self.unused_ips)}")
    
    def generate_report(self, output_file=None):
        """Generate detailed report of unused IPs"""
        report = "\n" + "="*60 + "\n"
        report += "UNUSED IP ADDRESS DETECTION REPORT\n"
        report += "="*60 + "\n"
        report += f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Network Range: {self.network_range}\n"
        report += f"Total IPs: {len(self.all_ips)}\n"
        report += f"Active IPs: {len(self.used_ips)}\n"
        report += f"Unused IPs: {len(self.unused_ips)}\n"
        report += "="*60 + "\n\n"
        
        if self.used_ips:
            report += "ACTIVE IP ADDRESSES:\n"
            report += "-"*60 + "\n"
            for ip in sorted(self.used_ips, key=lambda x: ipaddress.ip_address(x)):
                report += f"  {ip}\n"
            report += "\n"
        
        if self.unused_ips:
            report += "UNUSED/AVAILABLE IP ADDRESSES:\n"
            report += "-"*60 + "\n"
            for ip in sorted(self.unused_ips, key=lambda x: ipaddress.ip_address(x)):
                report += f"  {ip}\n"
            report += "\n"
        
        report += "="*60 + "\n"
        
        print(report)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                print(f"[*] Report saved to: {output_file}")
            except Exception as e:
                print(f"[!] Error saving report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Detect unused IP addresses in a network range',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -n 192.168.1.0/24 -m ping
  %(prog)s -n 10.0.0.0/24 -m arp -o unused_ips.txt
  %(prog)s -n 172.16.0.0/24 -m nmap -w 100
        """)
    
    parser.add_argument('-n', '--network', required=True, 
                        help='Network range in CIDR notation (e.g., 192.168.1.0/24)')
    parser.add_argument('-m', '--method', choices=['ping', 'arp', 'nmap', 'all'], 
                        default='ping', help='Scanning method (default: ping)')
    parser.add_argument('-t', '--timeout', type=int, default=2, 
                        help='Timeout in seconds for each ping (default: 2)')
    parser.add_argument('-w', '--workers', type=int, default=50, 
                        help='Number of concurrent workers for ping sweep (default: 50)')
    parser.add_argument('-o', '--output', help='Output file for report')
    
    args = parser.parse_args()
    
    detector = UnusedIPDetector(args.network, args.timeout)
    
    if not detector.validate_network():
        sys.exit(1)
    
    print(f"\n[*] Starting scan using method: {args.method}\n")
    
    # Perform scanning based on selected method
    if args.method == 'ping':
        detector.concurrent_ping_sweep(args.workers)
    elif args.method == 'arp':
        if not detector.arp_scan():
            print("[!] Falling back to ping sweep...")
            detector.concurrent_ping_sweep(args.workers)
    elif args.method == 'nmap':
        if not detector.nmap_scan():
            print("[!] Falling back to ping sweep...")
            detector.concurrent_ping_sweep(args.workers)
    elif args.method == 'all':
        # Try all methods
        detector.arp_scan()
        detector.nmap_scan()
        detector.concurrent_ping_sweep(args.workers)
    
    detector.identify_unused_ips()
    detector.generate_report(args.output)


if __name__ == '__main__':
    main()
