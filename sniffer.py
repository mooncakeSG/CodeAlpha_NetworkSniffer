#!/usr/bin/env python3
"""
Basic Network Sniffer with Python
A tool to capture and analyze live network packets
"""

import sys
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from scapy.layers.inet import Ether
import argparse
import json

class NetworkSniffer:
    def __init__(self, interface=None, filter_string=None, count=0, timeout=None, save_file=None):
        self.interface = interface
        self.filter_string = filter_string
        self.count = count
        self.timeout = timeout
        self.save_file = save_file
        self.packet_count = 0
        self.packets = []
        
    def get_protocol(self, packet):
        """Determine the protocol of the packet"""
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        else:
            return "OTHER"
    
    def get_port_info(self, packet):
        """Extract port information from packet"""
        if TCP in packet:
            return f"{packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet:
            return f"{packet[UDP].sport} -> {packet[UDP].dport}"
        return "N/A"
    
    def get_payload_info(self, packet):
        """Extract and analyze payload information"""
        if Raw in packet:
            payload = packet[Raw].load
            # Try to decode as string, fallback to hex
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                if len(payload_str) > 100:
                    payload_str = payload_str[:100] + "..."
                return payload_str
            except:
                return f"<{len(payload)} bytes>"
        return "No payload"
    
    def analyze_packet(self, packet):
        """Detailed packet analysis"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'protocol': 'UNKNOWN',
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'ports': 'N/A',
            'size': len(packet),
            'payload_info': 'No payload'
        }
        
        # IP Layer analysis
        if IP in packet:
            ip_layer = packet[IP]
            analysis['src_ip'] = ip_layer.src
            analysis['dst_ip'] = ip_layer.dst
            analysis['protocol'] = self.get_protocol(packet)
            analysis['ports'] = self.get_port_info(packet)
            analysis['payload_info'] = self.get_payload_info(packet)
            
            # Protocol-specific analysis
            if TCP in packet:
                tcp_layer = packet[TCP]
                analysis['tcp_flags'] = str(tcp_layer.flags)
            elif UDP in packet:
                udp_layer = packet[UDP]
                analysis['udp_length'] = udp_layer.len
                
        return analysis
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        self.packet_count += 1
        
        # Analyze the packet
        analysis = self.analyze_packet(packet)
        
        # Print packet information
        print(f"\n[+] Packet #{self.packet_count}")
        print(f"    Time: {analysis['timestamp']}")
        print(f"    Protocol: {analysis['protocol']}")
        print(f"    Source: {analysis['src_ip']}")
        print(f"    Destination: {analysis['dst_ip']}")
        print(f"    Ports: {analysis['ports']}")
        print(f"    Size: {analysis['size']} bytes")
        print(f"    Payload: {analysis['payload_info']}")
        
        # Store packet for saving
        if self.save_file:
            self.packets.append(packet)
        
        # Print separator
        print("-" * 60)
    
    def start_sniffing(self):
        """Start the packet sniffing process"""
        print(f"[*] Starting Network Sniffer...")
        print(f"[*] Interface: {self.interface or 'Default'}")
        print(f"[*] Filter: {self.filter_string or 'None'}")
        print(f"[*] Count: {self.count or 'Unlimited'}")
        print(f"[*] Timeout: {self.timeout or 'None'} seconds")
        print(f"[*] Save to file: {self.save_file or 'No'}")
        print("=" * 60)
        
        try:
            # Start sniffing
            sniff(
                iface=self.interface,
                filter=self.filter_string,
                count=self.count,
                timeout=self.timeout,
                prn=self.packet_callback,
                store=0
            )
            
            # Save packets if requested
            if self.save_file and self.packets:
                from scapy.utils import wrpcap
                wrpcap(self.save_file, self.packets)
                print(f"\n[+] Saved {len(self.packets)} packets to {self.save_file}")
                
        except KeyboardInterrupt:
            print(f"\n[!] Sniffing stopped by user")
            if self.save_file and self.packets:
                from scapy.utils import wrpcap
                wrpcap(self.save_file, self.packets)
                print(f"[+] Saved {len(self.packets)} packets to {self.save_file}")
        except Exception as e:
            print(f"[!] Error during sniffing: {e}")
            return False
        
        print(f"\n[+] Sniffing completed. Total packets captured: {self.packet_count}")
        return True

def list_interfaces():
    """List available network interfaces"""
    from scapy.arch import get_if_list
    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    print()

def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer with Python")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g., 'tcp', 'udp port 53')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-t", "--timeout", type=int, help="Timeout in seconds")
    parser.add_argument("-s", "--save", help="Save packets to PCAP file")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List available interfaces")
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        list_interfaces()
        return
    
    # Create sniffer instance
    sniffer = NetworkSniffer(
        interface=args.interface,
        filter_string=args.filter,
        count=args.count,
        timeout=args.timeout,
        save_file=args.save
    )
    
    # Start sniffing
    sniffer.start_sniffing()

if __name__ == "__main__":
    main() 