#!/usr/bin/env python3
"""
Orphan User Detection Script
Author: Riantsoa RAJHONSON
Description: Detects orphan user accounts in Active Directory and local systems
"""

import argparse
import sys


class OrphanUserDetector:
    def __init__(self, domain_controller, username, password):
        self.domain_controller = domain_controller
        self.username = username
        self.password = password
        self.orphan_users = []
        self._ldap_available = None
        self._paramiko_available = None
        self._ldap_import_error = None
        self._paramiko_import_error = None

    def _ensure_ldap(self):
        """Lazy import ldap3 so Linux-only scan works without ldap libs."""
        if self._ldap_available is not None:
            return self._ldap_available
        try:
            from ldap3 import Server, Connection, ALL, SUBTREE
            self._Server = Server
            self._Connection = Connection
            self._ALL = ALL
            self._SUBTREE = SUBTREE
            self._ldap_available = True
        except ImportError as e:
            self._ldap_import_error = str(e)
            self._ldap_available = False
        return self._ldap_available

    def _ensure_paramiko(self):
        """Lazy import paramiko so AD-only scan works without ssh libs."""
        if self._paramiko_available is not None:
            return self._paramiko_available
        try:
            import paramiko
            self._paramiko = paramiko
            self._paramiko_available = True
        except ImportError as e:
            self._paramiko_import_error = str(e)
            self._paramiko_available = False
        return self._paramiko_available
    
    def connect_ldap(self):
        """Connect to Active Directory via LDAP"""
        if not self._ensure_ldap():
            print(f"LDAP module unavailable: {self._ldap_import_error}")
            return None
        try:
            server = self._Server(self.domain_controller, get_info=self._ALL)
            conn = self._Connection(server, user=self.username, password=self.password, auto_bind=True)
            return conn
        except Exception as e:
            print(f"LDAP Connection Error: {e}")
            return None
    
    def detect_ad_orphans(self):
        """Detect orphan users in Active Directory"""
        conn = self.connect_ldap()
        if not conn:
            return
        
        try:
            search_base = 'DC=' + ',DC='.join(self.domain_controller.split('.'))
            conn.search(
                search_base=search_base,
                search_filter='(&(objectClass=user)(objectCategory=person))',
                search_scope=self._SUBTREE,
                attributes=['sAMAccountName', 'lastLogon', 'whenCreated', 'memberOf']
            )
            
            for entry in conn.entries:
                # Check if user has no group memberships (potential orphan)
                member_of = entry.memberOf.value
                if not member_of:
                    self.orphan_users.append({
                        'username': str(entry.sAMAccountName),
                        'created': str(entry.whenCreated),
                        'last_logon': str(entry.lastLogon) if entry.lastLogon else 'Never',
                        'type': 'AD Orphan'
                    })
            
            conn.unbind()
        except Exception as e:
            print(f"Error detecting AD orphans: {e}")
    
    def check_linux_orphans(self, host, ssh_user, ssh_password):
        """Check for orphan users on Linux systems"""
        if not self._ensure_paramiko():
            print(f"Paramiko module unavailable: {self._paramiko_import_error}")
            return
        try:
            ssh = self._paramiko.SSHClient()
            ssh.set_missing_host_key_policy(self._paramiko.AutoAddPolicy())
            ssh.connect(host, username=ssh_user, password=ssh_password)
            
            # Check /etc/passwd for users without valid shells or home directories
            stdin, stdout, stderr = ssh.exec_command(
                "awk -F: '($7 != \"/sbin/nologin\" && $7 != \"/bin/false\") {print $1,$6,$7}' /etc/passwd"
            )
            
            users = stdout.read().decode().split('\n')
            for user_info in users:
                if user_info:
                    parts = user_info.split()
                    if len(parts) >= 3:
                        username = parts[0]
                        # Check if home directory exists
                        stdin, stdout, stderr = ssh.exec_command(f"test -d {parts[1]} && echo 'exists' || echo 'missing'")
                        result = stdout.read().decode().strip()
                        
                        if result == 'missing':
                            self.orphan_users.append({
                                'username': username,
                                'host': host,
                                'issue': 'Missing home directory',
                                'type': 'Linux Orphan'
                            })
            
            ssh.close()
        except Exception as e:
            print(f"Error checking Linux orphans on {host}: {e}")
    
    def generate_report(self, output_file=None):
        """Generate report of orphan users"""
        report = "\n=== ORPHAN USER DETECTION REPORT ===\n"
        report += f"Total Orphan Users Found: {len(self.orphan_users)}\n\n"
        
        for user in self.orphan_users:
            report += f"Type: {user['type']}\n"
            report += f"Username: {user['username']}\n"
            for key, value in user.items():
                if key not in ['type', 'username']:
                    report += f"  {key}: {value}\n"
            report += "-" * 50 + "\n"
        
        print(report)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                print(f"\nReport saved to: {output_file}")
            except Exception as e:
                print(f"Error saving report: {e}")


def main():
    parser = argparse.ArgumentParser(description='Detect orphan user accounts')
    parser.add_argument('-dc', '--domain-controller', help='Domain controller address')
    parser.add_argument('-u', '--username', help='Domain admin username')
    parser.add_argument('-p', '--password', help='Domain admin password')
    parser.add_argument('-lh', '--linux-hosts', nargs='+', help='Linux hosts to check')
    parser.add_argument('-lu', '--linux-user', help='Linux SSH username')
    parser.add_argument('-lp', '--linux-password', help='Linux SSH password')
    parser.add_argument('-o', '--output', help='Output file for report')
    
    args = parser.parse_args()
    
    has_ad_args = any([args.domain_controller, args.username, args.password])
    has_linux_args = bool(args.linux_hosts)

    if not has_ad_args and not has_linux_args:
        parser.error('Provide AD credentials (-dc -u -p), Linux targets (-lh -lu -lp), or both.')

    if has_ad_args and not all([args.domain_controller, args.username, args.password]):
        parser.error('AD scan requires -dc, -u and -p together.')

    if has_linux_args and not all([args.linux_user, args.linux_password]):
        parser.error('Linux scan requires -lh with -lu and -lp.')

    detector = OrphanUserDetector(args.domain_controller, args.username, args.password)

    if all([args.domain_controller, args.username, args.password]):
        print("[*] Detecting AD orphan users...")
        detector.detect_ad_orphans()

    if args.linux_hosts:
        print("[*] Checking Linux systems...")
        for host in args.linux_hosts:
            print(f"  Checking {host}...")
            detector.check_linux_orphans(host, args.linux_user, args.linux_password)
    
    detector.generate_report(args.output)


if __name__ == '__main__':
    main()
