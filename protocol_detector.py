#!/usr/bin/env python3
"""
Protocol Detector - Inspired by Above Network Security Sniffer
Detects various network protocols and potential security vulnerabilities
"""

import re
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, DHCP, BOOTP, ARP, Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP
from scapy.layers.tls.all import TLS
import struct

class ProtocolDetector:
    def __init__(self):
        self.protocols_detected = set()
        self.security_alerts = []
        self.connection_tracker = {}
        
        # Common port mappings
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
            67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
            123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
            389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
            514: "SYSLOG", 515: "LPR", 587: "SMTP", 636: "LDAPS",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "ORACLE",
            3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC",
            6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 9000: "JENKINS"
        }
        
        # Security patterns
        self.security_patterns = {
            'sql_injection': [
                r"(\b(union|select|insert|update|delete|drop|create|alter)\b)",
                r"(\b(and|or)\b\s+\d+\s*=\s*\d+)",
                r"(\b(and|or)\b\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"])"
            ],
            'xss': [
                r"(<script[^>]*>.*?</script>)",
                r"(javascript:.*?)",
                r"(on\w+\s*=\s*['\"].*?['\"])"
            ],
            'path_traversal': [
                r"(\.\./\.\./)",
                r"(\.\.\\)",
                r"(\.\.%2f)",
                r"(\.\.%5c)"
            ],
            'command_injection': [
                r"(\b(cmd|command|exec|system|shell)\b)",
                r"(\b(ping|nslookup|traceroute|netstat)\b)",
                r"(\b(rm|del|format|shutdown)\b)"
            ]
        }
    
    def detect_protocol(self, packet):
        """Main protocol detection method"""
        protocols = []
        security_issues = []
        
        # Layer 2 protocols
        if Ether in packet:
            protocols.extend(self._detect_l2_protocols(packet))
        
        # Layer 3 protocols
        if IP in packet:
            protocols.extend(self._detect_l3_protocols(packet))
        
        # Layer 4 protocols
        if TCP in packet:
            protocols.extend(self._detect_tcp_protocols(packet))
        elif UDP in packet:
            protocols.extend(self._detect_udp_protocols(packet))
        elif ICMP in packet:
            protocols.extend(self._detect_icmp_protocols(packet))
        
        # Application layer protocols
        protocols.extend(self._detect_application_protocols(packet))
        
        # Security analysis
        security_issues.extend(self._analyze_security(packet))
        
        return protocols, security_issues
    
    def _detect_l2_protocols(self, packet):
        """Detect Layer 2 protocols"""
        protocols = []
        eth = packet[Ether]
        
        # Check for ARP
        if eth.type == 0x0806:
            protocols.append("ARP")
        
        # Check for VLAN
        if eth.type == 0x8100:
            protocols.append("VLAN")
        
        # Check for IPv6
        if eth.type == 0x86DD:
            protocols.append("IPv6")
        
        return protocols
    
    def _detect_l3_protocols(self, packet):
        """Detect Layer 3 protocols"""
        protocols = []
        ip = packet[IP]
        
        # Check IP version
        if ip.version == 4:
            protocols.append("IPv4")
        elif ip.version == 6:
            protocols.append("IPv6")
        
        # Check for fragmentation
        if ip.frag != 0:
            protocols.append("IP-FRAGMENT")
        
        # Check TTL for potential traceroute
        if ip.ttl <= 1:
            protocols.append("TRACEROUTE")
        
        return protocols
    
    def _detect_tcp_protocols(self, packet):
        """Detect TCP-based protocols"""
        protocols = []
        tcp = packet[TCP]
        
        # Check common ports
        if tcp.dport in self.common_ports:
            protocols.append(self.common_ports[tcp.dport])
        if tcp.sport in self.common_ports:
            protocols.append(self.common_ports[tcp.sport])
        
        # Check TCP flags for specific behaviors
        if tcp.flags & 0x02:  # SYN
            if tcp.flags & 0x10:  # ACK
                protocols.append("TCP-SYN-ACK")
            else:
                protocols.append("TCP-SYN")
        
        if tcp.flags & 0x04:  # RST
            protocols.append("TCP-RST")
        
        if tcp.flags & 0x01:  # FIN
            protocols.append("TCP-FIN")
        
        # Check for port scanning patterns
        if self._is_port_scan(packet):
            protocols.append("PORT-SCAN")
        
        return protocols
    
    def _detect_udp_protocols(self, packet):
        """Detect UDP-based protocols"""
        protocols = []
        udp = packet[UDP]
        
        # Check common ports
        if udp.dport in self.common_ports:
            protocols.append(self.common_ports[udp.dport])
        if udp.sport in self.common_ports:
            protocols.append(self.common_ports[udp.sport])
        
        # DNS detection
        if udp.dport == 53 or udp.sport == 53:
            if DNS in packet:
                protocols.append("DNS")
        
        # DHCP detection
        if udp.dport == 67 or udp.dport == 68:
            if DHCP in packet or BOOTP in packet:
                protocols.append("DHCP")
        
        # NTP detection
        if udp.dport == 123 or udp.sport == 123:
            if NTP in packet:
                protocols.append("NTP")
        
        # SNMP detection
        if udp.dport == 161 or udp.dport == 162:
            if SNMP in packet:
                protocols.append("SNMP")
        
        return protocols
    
    def _detect_icmp_protocols(self, packet):
        """Detect ICMP-based protocols"""
        protocols = []
        icmp = packet[ICMP]
        
        icmp_types = {
            0: "ICMP-ECHO-REPLY",
            3: "ICMP-DEST-UNREACH",
            5: "ICMP-REDIRECT",
            8: "ICMP-ECHO-REQUEST",
            11: "ICMP-TIME-EXCEEDED",
            13: "ICMP-TIMESTAMP",
            14: "ICMP-TIMESTAMP-REPLY",
            15: "ICMP-INFO-REQUEST",
            16: "ICMP-INFO-REPLY",
            17: "ICMP-ADDRESS-MASK-REQUEST",
            18: "ICMP-ADDRESS-MASK-REPLY"
        }
        
        if icmp.type in icmp_types:
            protocols.append(icmp_types[icmp.type])
        
        return protocols
    
    def _detect_application_protocols(self, packet):
        """Detect application layer protocols"""
        protocols = []
        
        # HTTP detection
        if Raw in packet:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
            
            # HTTP
            if payload.startswith(('get ', 'post ', 'put ', 'delete ', 'head ')):
                protocols.append("HTTP")
            elif payload.startswith('http/'):
                protocols.append("HTTP-RESPONSE")
            
            # FTP
            if any(cmd in payload for cmd in ['user ', 'pass ', 'quit', 'list', 'retr']):
                protocols.append("FTP")
            
            # SMTP
            if any(cmd in payload for cmd in ['helo', 'ehlo', 'mail from:', 'rcpt to:', 'data']):
                protocols.append("SMTP")
            
            # POP3
            if any(cmd in payload for cmd in ['user ', 'pass ', 'list', 'retr', 'quit']):
                protocols.append("POP3")
            
            # IMAP
            if any(cmd in payload for cmd in ['login', 'select', 'fetch', 'store']):
                protocols.append("IMAP")
        
        # TLS/SSL detection
        if TLS in packet:
            protocols.append("TLS/SSL")
        
        return protocols
    
    def _is_port_scan(self, packet):
        """Detect potential port scanning activity"""
        if IP in packet and TCP in packet:
            ip = packet[IP]
            tcp = packet[TCP]
            
            # Create connection key
            conn_key = f"{ip.src}:{ip.dst}"
            
            if conn_key not in self.connection_tracker:
                self.connection_tracker[conn_key] = {
                    'ports': set(),
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now()
                }
            
            self.connection_tracker[conn_key]['ports'].add(tcp.dport)
            self.connection_tracker[conn_key]['last_seen'] = datetime.now()
            
            # Check if this looks like a port scan
            ports = self.connection_tracker[conn_key]['ports']
            time_diff = (datetime.now() - self.connection_tracker[conn_key]['first_seen']).total_seconds()
            
            # If many ports in short time, likely a scan
            if len(ports) > 10 and time_diff < 60:
                return True
        
        return False
    
    def _analyze_security(self, packet):
        """Analyze packet for security issues"""
        security_issues = []
        
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Check for SQL injection
                for pattern in self.security_patterns['sql_injection']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        security_issues.append("SQL_INJECTION_ATTEMPT")
                        break
                
                # Check for XSS
                for pattern in self.security_patterns['xss']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        security_issues.append("XSS_ATTEMPT")
                        break
                
                # Check for path traversal
                for pattern in self.security_patterns['path_traversal']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        security_issues.append("PATH_TRAVERSAL_ATTEMPT")
                        break
                
                # Check for command injection
                for pattern in self.security_patterns['command_injection']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        security_issues.append("COMMAND_INJECTION_ATTEMPT")
                        break
                
            except UnicodeDecodeError:
                pass
        
        # Check for suspicious TCP flags
        if TCP in packet:
            tcp = packet[TCP]
            if tcp.flags == 0:  # NULL scan
                security_issues.append("NULL_SCAN")
            elif tcp.flags == 0x01:  # FIN scan
                security_issues.append("FIN_SCAN")
            elif tcp.flags == 0x02:  # SYN scan
                security_issues.append("SYN_SCAN")
        
        # Check for suspicious ICMP
        if ICMP in packet:
            icmp = packet[ICMP]
            if icmp.type == 8 and len(packet) > 1000:  # Large ping
                security_issues.append("PING_OF_DEATH")
        
        return security_issues
    
    def get_statistics(self):
        """Get detection statistics"""
        return {
            'protocols_detected': len(self.protocols_detected),
            'security_alerts': len(self.security_alerts),
            'active_connections': len(self.connection_tracker),
            'protocols': list(self.protocols_detected),
            'alerts': self.security_alerts
        } 