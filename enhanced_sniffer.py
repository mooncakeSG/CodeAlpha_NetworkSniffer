#!/usr/bin/env python3
"""
Enhanced Network Sniffer - Inspired by Above
A comprehensive network security analysis tool
"""

import sys
import time
import json
import threading
from datetime import datetime
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import argparse
import signal

from protocol_detector import ProtocolDetector

class EnhancedNetworkSniffer:
    def __init__(self, interface=None, filter_string=None, count=0, timeout=None, save_file=None, verbose=False):
        self.interface = interface
        self.filter_string = filter_string
        self.count = count
        self.timeout = timeout
        self.save_file = save_file
        self.verbose = verbose
        
        # Core components
        self.protocol_detector = ProtocolDetector()
        self.packet_count = 0
        self.packets = []
        
        # Statistics tracking
        self.stats = {
            'total_packets': 0,
            'protocols': Counter(),
            'security_alerts': Counter(),
            'top_talkers': Counter(),
            'top_ports': Counter(),
            'connection_pairs': Counter(),
            'packet_sizes': [],
            'start_time': datetime.now()
        }
        
        # Real-time monitoring
        self.monitoring = {
            'port_scans': [],
            'security_events': [],
            'unusual_activity': []
        }
        
        # Signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        self.running = True
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n[!] Stopping sniffer...")
        self.running = False
    
    def packet_callback(self, packet):
        """Enhanced packet analysis callback"""
        if not self.running:
            return
        
        self.packet_count += 1
        self.stats['total_packets'] += 1
        
        # Basic packet analysis
        analysis = self.analyze_packet(packet)
        
        # Protocol detection
        protocols, security_issues = self.protocol_detector.detect_protocol(packet)
        
        # Update statistics
        self.update_statistics(packet, analysis, protocols, security_issues)
        
        # Store packet if saving
        if self.save_file:
            self.packets.append(packet)
        
        # Display packet information
        self.display_packet(analysis, protocols, security_issues)
        
        # Check for monitoring conditions
        self.check_monitoring_conditions(packet, protocols, security_issues)
        
        # Periodic statistics display
        if self.packet_count % 50 == 0:
            self.display_statistics()
    
    def analyze_packet(self, packet):
        """Comprehensive packet analysis"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'protocol': 'UNKNOWN',
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'size': len(packet),
            'payload_info': 'No payload',
            'tcp_flags': None,
            'ttl': None,
            'tos': None
        }
        
        if IP in packet:
            ip_layer = packet[IP]
            analysis['src_ip'] = ip_layer.src
            analysis['dst_ip'] = ip_layer.dst
            analysis['ttl'] = ip_layer.ttl
            analysis['tos'] = ip_layer.tos
            
            if TCP in packet:
                tcp_layer = packet[TCP]
                analysis['protocol'] = 'TCP'
                analysis['src_port'] = tcp_layer.sport
                analysis['dst_port'] = tcp_layer.dport
                analysis['tcp_flags'] = str(tcp_layer.flags)
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                analysis['protocol'] = 'UDP'
                analysis['src_port'] = udp_layer.sport
                analysis['dst_port'] = udp_layer.dport
                
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                analysis['protocol'] = 'ICMP'
                analysis['src_port'] = icmp_layer.type
                analysis['dst_port'] = icmp_layer.code
            
            # Payload analysis
            if Raw in packet:
                payload = packet[Raw].load
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if len(payload_str) > 100:
                        payload_str = payload_str[:100] + "..."
                    analysis['payload_info'] = payload_str
                except:
                    analysis['payload_info'] = f"<{len(payload)} bytes>"
        
        return analysis
    
    def update_statistics(self, packet, analysis, protocols, security_issues):
        """Update comprehensive statistics"""
        # Protocol statistics
        for protocol in protocols:
            self.stats['protocols'][protocol] += 1
        
        # Security alerts
        for alert in security_issues:
            self.stats['security_alerts'][alert] += 1
        
        # Top talkers
        if analysis['src_ip'] != 'N/A':
            self.stats['top_talkers'][analysis['src_ip']] += 1
        if analysis['dst_ip'] != 'N/A':
            self.stats['top_talkers'][analysis['dst_ip']] += 1
        
        # Top ports
        if analysis['src_port'] != 'N/A':
            self.stats['top_ports'][analysis['src_port']] += 1
        if analysis['dst_port'] != 'N/A':
            self.stats['top_ports'][analysis['dst_port']] += 1
        
        # Connection pairs
        if analysis['src_ip'] != 'N/A' and analysis['dst_ip'] != 'N/A':
            conn_pair = f"{analysis['src_ip']} -> {analysis['dst_ip']}"
            self.stats['connection_pairs'][conn_pair] += 1
        
        # Packet sizes
        self.stats['packet_sizes'].append(analysis['size'])
    
    def display_packet(self, analysis, protocols, security_issues):
        """Display packet information"""
        if not self.verbose:
            return
        
        print(f"\n[+] Packet #{self.packet_count}")
        print(f"    Time: {analysis['timestamp']}")
        print(f"    Protocol: {analysis['protocol']}")
        print(f"    Source: {analysis['src_ip']}:{analysis['src_port']}")
        print(f"    Destination: {analysis['dst_ip']}:{analysis['dst_port']}")
        print(f"    Size: {analysis['size']} bytes")
        
        if protocols:
            print(f"    Detected Protocols: {', '.join(protocols)}")
        
        if security_issues:
            print(f"    ⚠️  Security Alerts: {', '.join(security_issues)}")
        
        if analysis['tcp_flags']:
            print(f"    TCP Flags: {analysis['tcp_flags']}")
        
        if analysis['payload_info'] != 'No payload':
            print(f"    Payload: {analysis['payload_info']}")
        
        print("-" * 80)
    
    def check_monitoring_conditions(self, packet, protocols, security_issues):
        """Check for conditions that need monitoring"""
        # Port scan detection
        if 'PORT-SCAN' in protocols:
            self.monitoring['port_scans'].append({
                'timestamp': datetime.now(),
                'source': packet[IP].src if IP in packet else 'Unknown',
                'protocols': protocols
            })
        
        # Security events
        if security_issues:
            self.monitoring['security_events'].append({
                'timestamp': datetime.now(),
                'source': packet[IP].src if IP in packet else 'Unknown',
                'alerts': security_issues,
                'protocols': protocols
            })
        
        # Unusual activity (large packets, unusual ports, etc.)
        if IP in packet:
            if len(packet) > 1500:  # Large packets
                self.monitoring['unusual_activity'].append({
                    'timestamp': datetime.now(),
                    'type': 'LARGE_PACKET',
                    'size': len(packet),
                    'source': packet[IP].src
                })
    
    def display_statistics(self):
        """Display comprehensive statistics"""
        print(f"\n{'='*80}")
        print(f"📊 NETWORK STATISTICS (Packets: {self.packet_count})")
        print(f"{'='*80}")
        
        # Top protocols
        print(f"\n🔍 TOP PROTOCOLS:")
        for protocol, count in self.stats['protocols'].most_common(10):
            print(f"    {protocol}: {count}")
        
        # Top talkers
        print(f"\n🌐 TOP TALKERS:")
        for ip, count in self.stats['top_talkers'].most_common(5):
            print(f"    {ip}: {count} packets")
        
        # Top ports
        print(f"\n🔌 TOP PORTS:")
        for port, count in self.stats['top_ports'].most_common(10):
            print(f"    {port}: {count} packets")
        
        # Security alerts
        if self.stats['security_alerts']:
            print(f"\n⚠️  SECURITY ALERTS:")
            for alert, count in self.stats['security_alerts'].most_common():
                print(f"    {alert}: {count}")
        
        # Monitoring events
        if self.monitoring['port_scans']:
            print(f"\n🔍 PORT SCANS DETECTED: {len(self.monitoring['port_scans'])}")
        
        if self.monitoring['security_events']:
            print(f"\n🚨 SECURITY EVENTS: {len(self.monitoring['security_events'])}")
        
        # Connection analysis
        print(f"\n🔗 TOP CONNECTIONS:")
        for conn, count in self.stats['connection_pairs'].most_common(5):
            print(f"    {conn}: {count} packets")
        
        # Packet size statistics
        if self.stats['packet_sizes']:
            avg_size = sum(self.stats['packet_sizes']) / len(self.stats['packet_sizes'])
            min_size = min(self.stats['packet_sizes'])
            max_size = max(self.stats['packet_sizes'])
            print(f"\n📦 PACKET SIZE STATS:")
            print(f"    Average: {avg_size:.1f} bytes")
            print(f"    Min: {min_size} bytes")
            print(f"    Max: {max_size} bytes")
        
        print(f"{'='*80}\n")
    
    def start_sniffing(self):
        """Start the enhanced packet sniffing process"""
        print(f"[*] Starting Enhanced Network Sniffer...")
        print(f"[*] Interface: {self.interface or 'Default'}")
        print(f"[*] Filter: {self.filter_string or 'None'}")
        print(f"[*] Count: {self.count or 'Unlimited'}")
        print(f"[*] Timeout: {self.timeout or 'None'} seconds")
        print(f"[*] Save to file: {self.save_file or 'No'}")
        print(f"[*] Verbose: {self.verbose}")
        print("=" * 80)
        
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
        except Exception as e:
            print(f"[!] Error during sniffing: {e}")
            return False
        
        # Final statistics
        self.display_final_report()
        return True
    
    def display_final_report(self):
        """Display final comprehensive report"""
        print(f"\n{'='*80}")
        print(f"📋 FINAL ANALYSIS REPORT")
        print(f"{'='*80}")
        
        runtime = datetime.now() - self.stats['start_time']
        print(f"\n⏱️  Runtime: {runtime}")
        print(f"📦 Total Packets: {self.packet_count}")
        
        # Protocol distribution
        total_protocols = sum(self.stats['protocols'].values())
        if total_protocols > 0:
            print(f"\n📊 Protocol Distribution:")
            for protocol, count in self.stats['protocols'].most_common():
                percentage = (count / total_protocols) * 100
                print(f"    {protocol}: {count} ({percentage:.1f}%)")
        
        # Security summary
        total_alerts = sum(self.stats['security_alerts'].values())
        if total_alerts > 0:
            print(f"\n🚨 Security Summary:")
            print(f"    Total Alerts: {total_alerts}")
            for alert, count in self.stats['security_alerts'].most_common():
                print(f"    {alert}: {count}")
        
        # Network topology insights
        print(f"\n🌐 Network Insights:")
        print(f"    Unique IPs: {len(self.stats['top_talkers'])}")
        print(f"    Active Ports: {len(self.stats['top_ports'])}")
        print(f"    Connections: {len(self.stats['connection_pairs'])}")
        
        # Recommendations
        self.generate_recommendations()
        
        print(f"{'='*80}")
    
    def generate_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Check for suspicious activity
        if self.stats['security_alerts']:
            recommendations.append("🔍 Review security alerts and investigate suspicious traffic")
        
        if self.monitoring['port_scans']:
            recommendations.append("🛡️  Consider implementing port scan detection and blocking")
        
        # Check for unusual protocols
        unusual_protocols = ['TELNET', 'FTP', 'SNMP']  # Protocols without encryption
        for protocol in unusual_protocols:
            if protocol in self.stats['protocols']:
                recommendations.append(f"🔒 Consider replacing {protocol} with encrypted alternatives")
        
        # Check for large packet volumes
        if self.stats['total_packets'] > 10000:
            recommendations.append("📈 High packet volume detected - consider traffic analysis")
        
        if recommendations:
            print(f"\n💡 Recommendations:")
            for rec in recommendations:
                print(f"    {rec}")
        else:
            print(f"\n✅ No immediate security concerns detected")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Network Sniffer - Inspired by Above")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", help="BPF filter string")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-t", "--timeout", type=int, help="Timeout in seconds")
    parser.add_argument("-s", "--save", help="Save packets to PCAP file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List available interfaces")
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        print("\nAvailable network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        print()
        return
    
    # Create enhanced sniffer
    sniffer = EnhancedNetworkSniffer(
        interface=args.interface,
        filter_string=args.filter,
        count=args.count,
        timeout=args.timeout,
        save_file=args.save,
        verbose=args.verbose
    )
    
    # Start sniffing
    sniffer.start_sniffing()

if __name__ == "__main__":
    main() 