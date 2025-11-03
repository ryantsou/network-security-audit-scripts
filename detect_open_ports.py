#!/usr/bin/env python3
"""
Open Port Detection Script
Author: Riantsoa RAJHONSON
Description: Scans hosts for open ports and identifies potentially vulnerable services
"""

import argparse
import sys
import socket
import concurrent.futures
from datetime import datetime

try:
    import nmap
    from scapy.all import sr1, IP, TCP, ICMP
except ImportError as e:
    print(f"Error: Missing required module - {e}")
    print("Please install requirements: pip install -r requirements.txt")
    sys.exit(1)


# Common port definitions
COMMON_PORTS = {
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt'
}

# Vulnerable/risky ports that should be carefully monitored
RISKY_PORTS = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5900]


class OpenPortScanner:
    def __init__(self, targets, ports=None, timeout=2):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.ports = ports if ports else list(COMMON_PORTS.keys())
        self.timeout = timeout
        self.scan_results = {}
        
    def check_host_alive(self, host):
        """Check if host is alive using ICMP ping"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, 80))
            sock.close()
            return True
        except:
            return False
    
    def scan_port_socket(self, host, port):
        """Scan a single port using socket connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'risky': port in RISKY_PORTS
                }
            return None
        except socket.error:
            return None
    
    def scan_port_scapy(self, host, port):
        """Scan port using Scapy for more detailed information"""
        try:
            # Create SYN packet
            packet = IP(dst=host)/TCP(dport=port, flags='S')
            response = sr1(packet, timeout=self.timeout, verbose=False)
            
            if response:
                if response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        # Send RST to close connection
                        rst = IP(dst=host)/TCP(dport=port, flags='R')
                        sr1(rst, timeout=self.timeout, verbose=False)
                        
                        service = COMMON_PORTS.get(port, 'Unknown')
                        return {
                            'port': port,
                            'state': 'open',
                            'service': service,
                            'risky': port in RISKY_PORTS
                        }
                    elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                        return None
            return None
        except Exception as e:
            return None
    
    def scan_host_nmap(self, host, ports_str):
        """Scan host using Nmap for comprehensive results"""
        try:
            nm = nmap.PortScanner()
            print(f"[*] Scanning {host} with Nmap...")
            nm.scan(host, ports_str, arguments='-sV -T4')
            
            results = []
            if host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        port_info = nm[host][proto][port]
                        if port_info['state'] == 'open':
                            results.append({
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'Unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'risky': port in RISKY_PORTS
                            })
            return results
        except Exception as e:
            print(f"[!] Nmap scan failed for {host}: {e}")
            return []
    
    def scan_host_concurrent(self, host, method='socket'):
        """Scan all ports on a host concurrently"""
        print(f"\n[*] Scanning {host}...")
        open_ports = []
        
        if method == 'socket':
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                future_to_port = {executor.submit(self.scan_port_socket, host, port): port 
                                  for port in self.ports}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        status = "[RISKY]" if result['risky'] else "[INFO]"
                        print(f"  {status} Port {result['port']}/tcp - {result['service']} - OPEN")
        
        elif method == 'scapy':
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(self.scan_port_scapy, host, port): port 
                                  for port in self.ports}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        status = "[RISKY]" if result['risky'] else "[INFO]"
                        print(f"  {status} Port {result['port']}/tcp - {result['service']} - OPEN")
        
        self.scan_results[host] = open_ports
        print(f"[*] Found {len(open_ports)} open ports on {host}")
        
    def scan_all_hosts(self, method='socket'):
        """Scan all target hosts"""
        print(f"[*] Starting port scan on {len(self.targets)} host(s)")
        print(f"[*] Ports to scan: {len(self.ports)}")
        print(f"[*] Method: {method}")
        
        for host in self.targets:
            if method == 'nmap':
                ports_str = ','.join(map(str, self.ports))
                results = self.scan_host_nmap(host, ports_str)
                self.scan_results[host] = results
                
                if results:
                    print(f"\n[*] Results for {host}:")
                    for result in results:
                        status = "[RISKY]" if result['risky'] else "[INFO]"
                        version_info = f" ({result.get('product', '')} {result.get('version', '')})" if result.get('version') else ""
                        print(f"  {status} Port {result['port']}/tcp - {result['service']}{version_info} - OPEN")
                    print(f"[*] Found {len(results)} open ports on {host}")
            else:
                self.scan_host_concurrent(host, method)
    
    def generate_report(self, output_file=None):
        """Generate detailed scan report"""
        report = "\n" + "="*70 + "\n"
        report += "OPEN PORT SCAN REPORT\n"
        report += "="*70 + "\n"
        report += f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Targets Scanned: {len(self.targets)}\n"
        report += f"Ports Scanned: {len(self.ports)}\n"
        report += "="*70 + "\n\n"
        
        total_open_ports = 0
        risky_ports_found = 0
        
        for host, ports in self.scan_results.items():
            total_open_ports += len(ports)
            risky_count = sum(1 for p in ports if p['risky'])
            risky_ports_found += risky_count
            
            report += f"\nHOST: {host}\n"
            report += "-"*70 + "\n"
            report += f"Total Open Ports: {len(ports)}\n"
            report += f"Risky Ports: {risky_count}\n\n"
            
            if ports:
                report += f"{'PORT':<8} {'SERVICE':<20} {'STATE':<10} {'RISK':<10}\n"
                report += "-"*70 + "\n"
                
                # Sort ports by port number
                sorted_ports = sorted(ports, key=lambda x: x['port'])
                
                for port_info in sorted_ports:
                    port = port_info['port']
                    service = port_info['service']
                    state = port_info['state']
                    risk = 'HIGH' if port_info['risky'] else 'LOW'
                    
                    # Add version info if available
                    if 'version' in port_info and port_info['version']:
                        service += f" ({port_info.get('product', '')} {port_info['version']})"
                    
                    report += f"{port:<8} {service:<20} {state:<10} {risk:<10}\n"
                
                report += "\n"
            else:
                report += "No open ports detected.\n\n"
        
        report += "="*70 + "\n"
        report += "SUMMARY\n"
        report += "="*70 + "\n"
        report += f"Total Hosts Scanned: {len(self.targets)}\n"
        report += f"Total Open Ports Found: {total_open_ports}\n"
        report += f"Total Risky Ports Found: {risky_ports_found}\n"
        report += "="*70 + "\n"
        
        print(report)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                print(f"\n[*] Report saved to: {output_file}")
            except Exception as e:
                print(f"[!] Error saving report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Scan hosts for open ports and identify vulnerable services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -m socket
  %(prog)s -t 192.168.1.1 192.168.1.2 -p 22,80,443 -m scapy
  %(prog)s -t 10.0.0.1 -m nmap -o scan_results.txt
  %(prog)s -t 192.168.1.1 --all-ports -m socket
        """)
    
    parser.add_argument('-t', '--targets', nargs='+', required=True,
                        help='Target host(s) to scan')
    parser.add_argument('-p', '--ports', 
                        help='Ports to scan (comma-separated, e.g., 22,80,443)')
    parser.add_argument('--all-ports', action='store_true',
                        help='Scan all ports (1-65535) - WARNING: Very slow!')
    parser.add_argument('-m', '--method', choices=['socket', 'scapy', 'nmap'],
                        default='socket', help='Scanning method (default: socket)')
    parser.add_argument('--timeout', type=int, default=2,
                        help='Timeout in seconds for each connection (default: 2)')
    parser.add_argument('-o', '--output', help='Output file for report')
    
    args = parser.parse_args()
    
    # Parse ports
    if args.all_ports:
        ports = list(range(1, 65536))
        print("[!] Scanning ALL ports (1-65535). This will take a very long time!")
    elif args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("Error: Invalid port format. Use comma-separated numbers (e.g., 22,80,443)")
            sys.exit(1)
    else:
        ports = list(COMMON_PORTS.keys())
        print(f"[*] Using default common ports: {len(ports)} ports")
    
    scanner = OpenPortScanner(args.targets, ports, args.timeout)
    scanner.scan_all_hosts(args.method)
    scanner.generate_report(args.output)


if __name__ == '__main__':
    main()
