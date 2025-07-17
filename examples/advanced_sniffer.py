#!/usr/bin/env python3
"""
Advanced Network Sniffer Example
Demonstrates protocol-specific analysis and filtering
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from datetime import datetime
import json

class AdvancedSniffer:
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'dns_packets': 0,
            'other_packets': 0
        }
        self.connections = {}
    
    def analyze_tcp(self, packet):
        """Analyze TCP packet details"""
        tcp_layer = packet[TCP]
        connection_key = f"{packet[IP].src}:{tcp_layer.sport} -> {packet[IP].dst}:{tcp_layer.dport}"
        
        # Track connection state
        if connection_key not in self.connections:
            self.connections[connection_key] = {
                'start_time': datetime.now(),
                'packets': 0,
                'bytes': 0,
                'flags': set()
            }
        
        self.connections[connection_key]['packets'] += 1
        self.connections[connection_key]['bytes'] += len(packet)
        self.connections[connection_key]['flags'].add(str(tcp_layer.flags))
        
        # Check for HTTP
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            self.stats['http_packets'] += 1
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if payload.startswith(('GET', 'POST', 'HTTP')):
                    print(f"[HTTP] {connection_key}")
                    print(f"    Payload: {payload[:100]}...")
        
        return f"TCP {connection_key} (Flags: {tcp_layer.flags})"
    
    def analyze_udp(self, packet):
        """Analyze UDP packet details"""
        udp_layer = packet[UDP]
        
        # Check for DNS
        if udp_layer.dport == 53 or udp_layer.sport == 53:
            self.stats['dns_packets'] += 1
            print(f"[DNS] {packet[IP].src}:{udp_layer.sport} -> {packet[IP].dst}:{udp_layer.dport}")
        
        return f"UDP {packet[IP].src}:{udp_layer.sport} -> {packet[IP].dst}:{udp_layer.dport}"
    
    def analyze_icmp(self, packet):
        """Analyze ICMP packet details"""
        icmp_layer = packet[ICMP]
        icmp_type = icmp_layer.type
        
        type_names = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            8: "Echo Request",
            11: "Time Exceeded"
        }
        
        type_name = type_names.get(icmp_type, f"Type {icmp_type}")
        return f"ICMP {type_name} {packet[IP].src} -> {packet[IP].dst}"
    
    def packet_callback(self, packet):
        """Advanced packet analysis callback"""
        self.stats['total_packets'] += 1
        
        if IP not in packet:
            return
        
        ip_layer = packet[IP]
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        # Protocol analysis
        if TCP in packet:
            self.stats['tcp_packets'] += 1
            analysis = self.analyze_tcp(packet)
        elif UDP in packet:
            self.stats['udp_packets'] += 1
            analysis = self.analyze_udp(packet)
        elif ICMP in packet:
            self.stats['icmp_packets'] += 1
            analysis = self.analyze_icmp(packet)
        else:
            self.stats['other_packets'] += 1
            analysis = f"OTHER {ip_layer.src} -> {ip_layer.dst}"
        
        # Print packet info
        print(f"[{timestamp}] {analysis}")
        print(f"    Size: {len(packet)} bytes")
        
        # Print statistics every 10 packets
        if self.stats['total_packets'] % 10 == 0:
            self.print_stats()
    
    def print_stats(self):
        """Print current statistics"""
        print("\n" + "="*60)
        print("CURRENT STATISTICS:")
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"TCP: {self.stats['tcp_packets']} | UDP: {self.stats['udp_packets']} | ICMP: {self.stats['icmp_packets']}")
        print(f"HTTP: {self.stats['http_packets']} | DNS: {self.stats['dns_packets']} | Other: {self.stats['other_packets']}")
        print(f"Active Connections: {len(self.connections)}")
        print("="*60 + "\n")
    
    def print_final_report(self):
        """Print final analysis report"""
        print("\n" + "="*60)
        print("FINAL ANALYSIS REPORT")
        print("="*60)
        
        # Connection analysis
        print("\nTOP CONNECTIONS BY PACKET COUNT:")
        sorted_connections = sorted(
            self.connections.items(),
            key=lambda x: x[1]['packets'],
            reverse=True
        )[:5]
        
        for conn, data in sorted_connections:
            print(f"{conn}: {data['packets']} packets, {data['bytes']} bytes")
        
        # Protocol distribution
        total = self.stats['total_packets']
        if total > 0:
            print(f"\nPROTOCOL DISTRIBUTION:")
            print(f"TCP: {self.stats['tcp_packets']/total*100:.1f}%")
            print(f"UDP: {self.stats['udp_packets']/total*100:.1f}%")
            print(f"ICMP: {self.stats['icmp_packets']/total*100:.1f}%")
            print(f"Other: {self.stats['other_packets']/total*100:.1f}%")

def main():
    print("Advanced Network Sniffer Example")
    print("This example demonstrates:")
    print("- Protocol-specific analysis")
    print("- Connection tracking")
    print("- Statistics and reporting")
    print("- HTTP and DNS detection")
    print("- Real-time statistics")
    print("\nCapturing packets... (Press Ctrl+C to stop)")
    print("-" * 60)
    
    sniffer = AdvancedSniffer()
    
    try:
        # Capture packets with different filters
        print("\n1. Capturing all traffic (10 packets)...")
        sniff(count=10, prn=sniffer.packet_callback, store=0)
        
        print("\n2. Capturing TCP traffic only (5 packets)...")
        sniff(count=5, filter="tcp", prn=sniffer.packet_callback, store=0)
        
        print("\n3. Capturing DNS traffic (5 packets)...")
        sniff(count=5, filter="udp port 53", prn=sniffer.packet_callback, store=0)
        
    except KeyboardInterrupt:
        print("\nStopped by user")
    
    # Print final report
    sniffer.print_final_report()

if __name__ == "__main__":
    main() 