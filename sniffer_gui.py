#!/usr/bin/env python3
"""
GUI Network Sniffer with Python
A graphical interface for the network sniffer
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import json

class NetworkSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer - GUI")
        self.root.geometry("1000x700")
        
        # Sniffer state
        self.is_sniffing = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.packet_count = 0
        self.packets = []
        
        # Create GUI elements
        self.create_widgets()
        self.setup_packet_processing()
        
    def create_widgets(self):
        """Create and arrange GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Control Panel", padding="5")
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=20)
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
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=6, padx=(0, 5))
        
        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=7, padx=(0, 5))
        
        self.save_button = ttk.Button(control_frame, text="Save PCAP", command=self.save_pcap)
        self.save_button.grid(row=0, column=8, padx=(0, 5))
        
        self.clear_button = ttk.Button(control_frame, text="Clear", command=self.clear_display)
        self.clear_button.grid(row=0, column=9)
        
        # Statistics panel
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="5")
        stats_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.stats_text = tk.StringVar(value="Packets: 0 | TCP: 0 | UDP: 0 | ICMP: 0 | Other: 0")
        ttk.Label(stats_frame, textvariable=self.stats_text).grid(row=0, column=0, sticky=tk.W)
        
        # Packet display
        packet_frame = ttk.LabelFrame(main_frame, text="Captured Packets", padding="5")
        packet_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        packet_frame.columnconfigure(0, weight=1)
        packet_frame.rowconfigure(0, weight=1)
        
        # Create treeview for packets
        columns = ('Time', 'Protocol', 'Source', 'Destination', 'Ports', 'Size', 'Payload')
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=120)
        
        # Scrollbars
        packet_scrollbar_y = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        packet_scrollbar_x = ttk.Scrollbar(packet_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=packet_scrollbar_y.set, xscrollcommand=packet_scrollbar_x.set)
        
        # Grid treeview and scrollbars
        self.packet_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        packet_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        packet_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Packet details
        details_frame = ttk.LabelFrame(main_frame, text="Packet Details", padding="5")
        details_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD)
        self.details_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Bind treeview selection
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Load interfaces
        self.load_interfaces()
        
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
        
        # Add to queue for GUI processing
        self.packet_queue.put(analysis)
        
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
                analysis['ports'] = 'N/A'
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
    
    def add_packet_to_display(self, analysis):
        """Add packet to the treeview display"""
        self.packet_count += 1
        
        # Insert into treeview
        item = self.packet_tree.insert('', 'end', values=(
            analysis['timestamp'],
            analysis['protocol'],
            analysis['src_ip'],
            analysis['dst_ip'],
            analysis['ports'],
            analysis['size'],
            analysis['payload']
        ))
        
        # Update statistics
        self.update_statistics()
        
        # Auto-scroll to bottom
        self.packet_tree.see(item)
    
    def update_statistics(self):
        """Update statistics display"""
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        other_count = 0
        
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item)['values']
            protocol = values[1]
            if protocol == 'TCP':
                tcp_count += 1
            elif protocol == 'UDP':
                udp_count += 1
            elif protocol == 'ICMP':
                icmp_count += 1
            else:
                other_count += 1
        
        stats = f"Packets: {self.packet_count} | TCP: {tcp_count} | UDP: {udp_count} | ICMP: {icmp_count} | Other: {other_count}"
        self.stats_text.set(stats)
    
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
            details += f"Payload: {values[6]}\n\n"
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
        self.details_text.delete(1.0, tk.END)
        self.packet_count = 0
        self.packets = []
        self.update_statistics()

def main():
    root = tk.Tk()
    app = NetworkSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 