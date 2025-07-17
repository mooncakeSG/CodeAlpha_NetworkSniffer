#!/usr/bin/env python3
"""
Enhanced Network Sniffer GUI - Inspired by Above
A comprehensive network security analysis tool with graphical interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from datetime import datetime
import json
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation

from protocol_detector import ProtocolDetector
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

class EnhancedNetworkSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Network Sniffer - Inspired by Above")
        self.root.geometry("1400x900")
        
        # Core components
        self.protocol_detector = ProtocolDetector()
        self.is_sniffing = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.packet_count = 0
        self.packets = []
        
        # Statistics
        self.stats = {
            'protocols': Counter(),
            'security_alerts': Counter(),
            'top_talkers': Counter(),
            'top_ports': Counter(),
            'packet_sizes': [],
            'start_time': datetime.now()
        }
        
        # Real-time monitoring
        self.monitoring = {
            'port_scans': [],
            'security_events': [],
            'unusual_activity': []
        }
        
        # Create GUI elements
        self.create_widgets()
        self.setup_packet_processing()
        self.setup_charts()
        
    def create_widgets(self):
        """Create and arrange GUI widgets"""
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_capture_tab()
        self.create_analysis_tab()
        self.create_security_tab()
        self.create_monitoring_tab()
        
    def create_capture_tab(self):
        """Create the packet capture tab"""
        capture_frame = ttk.Frame(self.notebook)
        self.notebook.add(capture_frame, text="Packet Capture")
        
        # Control panel
        control_frame = ttk.LabelFrame(capture_frame, text="Capture Controls", padding="5")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=30)
        self.interface_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        
        # Filter
        ttk.Label(control_frame, text="Filter:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=20)
        self.filter_entry.grid(row=0, column=3, sticky=tk.W, padx=(0, 10))
        
        # Packet count
        ttk.Label(control_frame, text="Count:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        self.count_var = tk.StringVar(value="0")
        self.count_entry = ttk.Entry(control_frame, textvariable=self.count_var, width=10)
        self.count_entry.grid(row=0, column=5, sticky=tk.W, padx=(0, 10))
        
        # Buttons
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_sniffing)
        self.start_button.grid(row=0, column=6, padx=(0, 5))
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=7, padx=(0, 5))
        
        self.save_button = ttk.Button(control_frame, text="Save PCAP", command=self.save_pcap)
        self.save_button.grid(row=0, column=8, padx=(0, 5))
        
        self.clear_button = ttk.Button(control_frame, text="Clear", command=self.clear_display)
        self.clear_button.grid(row=0, column=9)
        
        # Statistics panel
        stats_frame = ttk.LabelFrame(capture_frame, text="Real-time Statistics", padding="5")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.stats_text = tk.StringVar(value="Packets: 0 | Protocols: 0 | Alerts: 0 | Runtime: 00:00:00")
        ttk.Label(stats_frame, textvariable=self.stats_text, font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        # Packet display
        packet_frame = ttk.LabelFrame(capture_frame, text="Captured Packets", padding="5")
        packet_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for packets
        columns = ('Time', 'Protocol', 'Source', 'Destination', 'Ports', 'Size', 'Protocols', 'Alerts')
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        column_widths = {'Time': 100, 'Protocol': 60, 'Source': 120, 'Destination': 120, 
                        'Ports': 80, 'Size': 60, 'Protocols': 150, 'Alerts': 100}
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        packet_scrollbar_y = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        packet_scrollbar_x = ttk.Scrollbar(packet_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=packet_scrollbar_y.set, xscrollcommand=packet_scrollbar_x.set)
        
        # Grid treeview and scrollbars
        self.packet_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        packet_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        packet_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        packet_frame.columnconfigure(0, weight=1)
        packet_frame.rowconfigure(0, weight=1)
        
        # Packet details
        details_frame = ttk.LabelFrame(capture_frame, text="Packet Details", padding="5")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind treeview selection
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Load interfaces
        self.load_interfaces()
        
    def create_analysis_tab(self):
        """Create the analysis tab with charts"""
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="Analysis")
        
        # Charts frame
        charts_frame = ttk.LabelFrame(analysis_frame, text="Network Analysis Charts", padding="5")
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create matplotlib figure
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.tight_layout(pad=3.0)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, charts_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initialize charts
        self.update_charts()
        
    def create_security_tab(self):
        """Create the security monitoring tab"""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security")
        
        # Security alerts frame
        alerts_frame = ttk.LabelFrame(security_frame, text="Security Alerts", padding="5")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Alerts treeview
        alert_columns = ('Time', 'Type', 'Source', 'Details', 'Severity')
        self.alert_tree = ttk.Treeview(alerts_frame, columns=alert_columns, show='headings', height=15)
        
        for col in alert_columns:
            self.alert_tree.heading(col, text=col)
            self.alert_tree.column(col, width=150)
        
        alert_scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=alert_scrollbar.set)
        
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alert_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Security summary
        summary_frame = ttk.LabelFrame(security_frame, text="Security Summary", padding="5")
        summary_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.security_summary = tk.StringVar(value="No security alerts detected")
        ttk.Label(summary_frame, textvariable=self.security_summary, font=("Arial", 10)).pack(anchor=tk.W)
        
    def create_monitoring_tab(self):
        """Create the monitoring tab"""
        monitoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitoring_frame, text="Monitoring")
        
        # Real-time monitoring
        monitor_frame = ttk.LabelFrame(monitoring_frame, text="Real-time Monitoring", padding="5")
        monitor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Monitoring text area
        self.monitor_text = scrolledtext.ScrolledText(monitor_frame, height=20, wrap=tk.WORD)
        self.monitor_text.pack(fill=tk.BOTH, expand=True)
        
        # Add initial monitoring message
        self.monitor_text.insert(tk.END, "Monitoring started...\n")
        self.monitor_text.see(tk.END)
        
    def setup_charts(self):
        """Setup matplotlib charts"""
        # Protocol distribution pie chart
        self.ax1.set_title('Protocol Distribution')
        self.ax1.pie([1], labels=['No Data'], autopct='%1.1f%%')
        
        # Top talkers bar chart
        self.ax2.set_title('Top Talkers')
        self.ax2.set_xlabel('IP Address')
        self.ax2.set_ylabel('Packet Count')
        
        # Top ports bar chart
        self.ax3.set_title('Top Ports')
        self.ax3.set_xlabel('Port')
        self.ax3.set_ylabel('Packet Count')
        
        # Security alerts bar chart
        self.ax4.set_title('Security Alerts')
        self.ax4.set_xlabel('Alert Type')
        self.ax4.set_ylabel('Count')
        
        plt.tight_layout()
        
    def update_charts(self):
        """Update all charts with current data"""
        # Clear all axes
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.clear()
        
        # Protocol distribution
        if self.stats['protocols']:
            protocols = list(self.stats['protocols'].keys())[:8]  # Top 8
            counts = list(self.stats['protocols'].values())[:8]
            self.ax1.pie(counts, labels=protocols, autopct='%1.1f%%')
        else:
            self.ax1.pie([1], labels=['No Data'], autopct='%1.1f%%')
        self.ax1.set_title('Protocol Distribution')
        
        # Top talkers
        if self.stats['top_talkers']:
            talkers = list(self.stats['top_talkers'].keys())[:5]
            counts = list(self.stats['top_talkers'].values())[:5]
            self.ax2.bar(range(len(talkers)), counts)
            self.ax2.set_xticks(range(len(talkers)))
            self.ax2.set_xticklabels(talkers, rotation=45)
        self.ax2.set_title('Top Talkers')
        self.ax2.set_ylabel('Packet Count')
        
        # Top ports
        if self.stats['top_ports']:
            ports = list(self.stats['top_ports'].keys())[:10]
            counts = list(self.stats['top_ports'].values())[:10]
            self.ax3.bar(range(len(ports)), counts)
            self.ax3.set_xticks(range(len(ports)))
            self.ax3.set_xticklabels(ports, rotation=45)
        self.ax3.set_title('Top Ports')
        self.ax3.set_ylabel('Packet Count')
        
        # Security alerts
        if self.stats['security_alerts']:
            alerts = list(self.stats['security_alerts'].keys())
            counts = list(self.stats['security_alerts'].values())
            self.ax4.bar(range(len(alerts)), counts, color='red')
            self.ax4.set_xticks(range(len(alerts)))
            self.ax4.set_xticklabels(alerts, rotation=45)
        self.ax4.set_title('Security Alerts')
        self.ax4.set_ylabel('Count')
        
        plt.tight_layout()
        self.canvas.draw()
        
    def load_interfaces(self):
        """Load available network interfaces"""
        try:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_combo.set(interfaces[0])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load interfaces: {e}")
    
    def setup_packet_processing(self):
        """Setup packet processing from queue"""
        def process_packets():
            while True:
                try:
                    packet_data = self.packet_queue.get(timeout=0.1)
                    if packet_data is None:  # Stop signal
                        break
                    self.add_packet_to_display(packet_data)
                except queue.Empty:
                    continue
        
        self.packet_processor = threading.Thread(target=process_packets, daemon=True)
        self.packet_processor.start()
    
    def packet_callback(self, packet):
        """Callback for captured packets"""
        if not self.is_sniffing:
            return
        
        # Analyze packet
        analysis = self.analyze_packet(packet)
        
        # Protocol detection
        protocols, security_issues = self.protocol_detector.detect_protocol(packet)
        
        # Add to queue for GUI processing
        self.packet_queue.put((analysis, protocols, security_issues))
        
        # Store packet
        self.packets.append(packet)
    
    def analyze_packet(self, packet):
        """Analyze packet and return structured data"""
        analysis = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'protocol': 'UNKNOWN',
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'ports': 'N/A',
            'size': len(packet),
            'payload': 'No payload',
            'raw_packet': packet
        }
        
        if IP in packet:
            ip_layer = packet[IP]
            analysis['src_ip'] = ip_layer.src
            analysis['dst_ip'] = ip_layer.dst
            
            if TCP in packet:
                analysis['protocol'] = 'TCP'
                analysis['ports'] = f"{packet[TCP].sport} -> {packet[TCP].dport}"
            elif UDP in packet:
                analysis['protocol'] = 'UDP'
                analysis['ports'] = f"{packet[UDP].sport} -> {packet[UDP].dport}"
            elif ICMP in packet:
                analysis['protocol'] = 'ICMP'
                analysis['ports'] = f"{packet[ICMP].type} -> {packet[ICMP].code}"
            else:
                analysis['protocol'] = 'OTHER'
                analysis['ports'] = 'N/A'
            
            if Raw in packet:
                payload = packet[Raw].load
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if len(payload_str) > 50:
                        payload_str = payload_str[:50] + "..."
                    analysis['payload'] = payload_str
                except:
                    analysis['payload'] = f"<{len(payload)} bytes>"
        
        return analysis
    
    def add_packet_to_display(self, packet_data):
        """Add packet to the treeview display"""
        analysis, protocols, security_issues = packet_data
        self.packet_count += 1
        
        # Update statistics
        for protocol in protocols:
            self.stats['protocols'][protocol] += 1
        
        for alert in security_issues:
            self.stats['security_alerts'][alert] += 1
        
        if analysis['src_ip'] != 'N/A':
            self.stats['top_talkers'][analysis['src_ip']] += 1
        if analysis['dst_ip'] != 'N/A':
            self.stats['top_talkers'][analysis['dst_ip']] += 1
        
        # Parse ports for statistics
        if analysis['ports'] != 'N/A':
            try:
                src_port, dst_port = analysis['ports'].split(' -> ')
                self.stats['top_ports'][src_port] += 1
                self.stats['top_ports'][dst_port] += 1
            except:
                pass
        
        self.stats['packet_sizes'].append(analysis['size'])
        
        # Insert into treeview
        protocols_str = ', '.join(protocols) if protocols else 'N/A'
        alerts_str = ', '.join(security_issues) if security_issues else 'N/A'
        
        item = self.packet_tree.insert('', 'end', values=(
            analysis['timestamp'],
            analysis['protocol'],
            analysis['src_ip'],
            analysis['dst_ip'],
            analysis['ports'],
            analysis['size'],
            protocols_str,
            alerts_str
        ))
        
        # Update statistics display
        self.update_statistics_display()
        
        # Add security alerts
        if security_issues:
            self.add_security_alert(analysis, security_issues)
        
        # Update monitoring
        self.update_monitoring(analysis, protocols, security_issues)
        
        # Auto-scroll to bottom
        self.packet_tree.see(item)
        
        # Update charts periodically
        if self.packet_count % 10 == 0:
            self.root.after(0, self.update_charts)
    
    def update_statistics_display(self):
        """Update the statistics display"""
        runtime = datetime.now() - self.stats['start_time']
        runtime_str = str(runtime).split('.')[0]  # Remove microseconds
        
        stats_text = f"Packets: {self.packet_count} | Protocols: {len(self.stats['protocols'])} | Alerts: {sum(self.stats['security_alerts'].values())} | Runtime: {runtime_str}"
        self.stats_text.set(stats_text)
    
    def add_security_alert(self, analysis, security_issues):
        """Add security alert to the alerts treeview"""
        for alert in security_issues:
            severity = "HIGH" if "INJECTION" in alert or "SCAN" in alert else "MEDIUM"
            
            self.alert_tree.insert('', 'end', values=(
                analysis['timestamp'],
                alert,
                analysis['src_ip'],
                f"{analysis['protocol']} {analysis['ports']}",
                severity
            ))
            
            # Update security summary
            total_alerts = sum(self.stats['security_alerts'].values())
            self.security_summary.set(f"Total Security Alerts: {total_alerts}")
    
    def update_monitoring(self, analysis, protocols, security_issues):
        """Update monitoring display"""
        timestamp = analysis['timestamp']
        
        # Add monitoring entries
        if 'PORT-SCAN' in protocols:
            self.monitor_text.insert(tk.END, f"[{timestamp}] 🔍 Port scan detected from {analysis['src_ip']}\n")
        
        if security_issues:
            self.monitor_text.insert(tk.END, f"[{timestamp}] ⚠️  Security alert: {', '.join(security_issues)} from {analysis['src_ip']}\n")
        
        if analysis['size'] > 1500:
            self.monitor_text.insert(tk.END, f"[{timestamp}] 📦 Large packet ({analysis['size']} bytes) from {analysis['src_ip']}\n")
        
        # Keep only last 100 lines
        lines = self.monitor_text.get("1.0", tk.END).split('\n')
        if len(lines) > 100:
            self.monitor_text.delete("1.0", tk.END)
            self.monitor_text.insert("1.0", '\n'.join(lines[-100:]))
        
        self.monitor_text.see(tk.END)
    
    def on_packet_select(self, event):
        """Handle packet selection in treeview"""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.packet_tree.item(item)['values']
        
        # Find corresponding packet
        index = int(item[1:]) - 1  # Extract index from item ID
        if 0 <= index < len(self.packets):
            packet = self.packets[index]
            
            # Display packet details
            details = f"Packet Details:\n"
            details += f"Time: {values[0]}\n"
            details += f"Protocol: {values[1]}\n"
            details += f"Source: {values[2]}\n"
            details += f"Destination: {values[3]}\n"
            details += f"Ports: {values[4]}\n"
            details += f"Size: {values[5]} bytes\n"
            details += f"Detected Protocols: {values[6]}\n"
            details += f"Security Alerts: {values[7]}\n\n"
            details += f"Raw Packet:\n{packet.show(dump=True)}"
            
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(1.0, details)
    
    def start_sniffing(self):
        """Start packet sniffing"""
        if self.is_sniffing:
            return
        
        try:
            count = int(self.count_var.get()) if self.count_var.get() else 0
        except ValueError:
            messagebox.showerror("Error", "Invalid packet count")
            return
        
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Reset statistics
        self.stats = {
            'protocols': Counter(),
            'security_alerts': Counter(),
            'top_talkers': Counter(),
            'top_ports': Counter(),
            'packet_sizes': [],
            'start_time': datetime.now()
        }
        
        # Clear displays
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.alert_tree.delete(*self.alert_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.monitor_text.delete(1.0, tk.END)
        self.monitor_text.insert(tk.END, "Monitoring started...\n")
        
        # Start sniffing in separate thread
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffer_thread.start()
    
    def sniff_packets(self):
        """Sniff packets in separate thread"""
        try:
            sniff(
                iface=self.interface_var.get() if self.interface_var.get() else None,
                filter=self.filter_var.get() if self.filter_var.get() else None,
                count=int(self.count_var.get()) if self.count_var.get() else 0,
                prn=self.packet_callback,
                store=0
            )
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Sniffing error: {e}"))
        finally:
            self.root.after(0, self.stop_sniffing)
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def save_pcap(self):
        """Save captured packets to PCAP file"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                from scapy.utils import wrpcap
                wrpcap(filename, self.packets)
                messagebox.showinfo("Success", f"Saved {len(self.packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")
    
    def clear_display(self):
        """Clear the packet display"""
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.alert_tree.delete(*self.alert_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.monitor_text.delete(1.0, tk.END)
        self.monitor_text.insert(tk.END, "Display cleared...\n")
        self.packet_count = 0
        self.packets = []
        
        # Reset statistics
        self.stats = {
            'protocols': Counter(),
            'security_alerts': Counter(),
            'top_talkers': Counter(),
            'top_ports': Counter(),
            'packet_sizes': [],
            'start_time': datetime.now()
        }
        
        self.update_statistics_display()
        self.update_charts()

def main():
    root = tk.Tk()
    app = EnhancedNetworkSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 