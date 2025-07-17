#!/usr/bin/env python3
"""
Simple Network Sniffer Example
A minimal example showing basic packet capture
"""

from scapy.all import sniff, IP, TCP, UDP

def simple_packet_callback(packet):
    """Simple callback function for packet analysis"""
    if IP in packet:
        ip_layer = packet[IP]
        proto = "OTHER"
        
        if TCP in packet:
            proto = "TCP"
            ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet:
            proto = "UDP"
            ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
        else:
            ports = "N/A"
        
        print(f"[{proto}] {ip_layer.src}:{ports} -> {ip_layer.dst}")

def main():
    print("Simple Network Sniffer Example")
    print("Capturing 10 packets...")
    print("Press Ctrl+C to stop early")
    print("-" * 50)
    
    try:
        # Capture 10 packets
        sniff(count=10, prn=simple_packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nStopped by user")
    
    print("-" * 50)
    print("Capture completed!")

if __name__ == "__main__":
    main() 