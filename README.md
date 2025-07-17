# Enhanced Network Sniffer - Inspired by Above

A comprehensive network security analysis tool built with Python and Scapy, inspired by the [Above](https://github.com/casterbyte/Above.git) project. This enhanced sniffer provides advanced protocol detection, security analysis, real-time monitoring, and threat detection capabilities.

## 🎯 Features

### 🔍 Advanced Protocol Detection
- **20+ Protocol Support**: TCP, UDP, ICMP, HTTP, HTTPS, DNS, DHCP, FTP, SSH, SMTP, POP3, IMAP, SNMP, NTP, TELNET, ARP, VLAN, IPv4, IPv6, TLS/SSL
- **Real-time Protocol Analysis**: Instant protocol identification as packets arrive
- **Application Layer Detection**: HTTP, FTP, SMTP, and other application protocols
- **Port-based Protocol Mapping**: Automatic protocol detection based on common ports

### 🛡️ Security Analysis & Threat Detection
- **Security Pattern Matching**: SQL injection, XSS, path traversal, command injection detection
- **Port Scan Detection**: Automatic detection of scanning activities
- **TCP Flag Analysis**: NULL, FIN, SYN scan detection
- **ICMP Attack Detection**: Ping of death and other ICMP-based attacks
- **Real-time Security Alerts**: Immediate notification of security threats

### 📊 Comprehensive Analytics
- **Real-time Statistics**: Protocol distribution, top talkers, port analysis
- **Connection Tracking**: Monitor connection states and behaviors
- **Packet Size Analysis**: Performance and bandwidth monitoring
- **Network Topology Mapping**: Identify network structure and relationships

### 🖥️ Enhanced User Interface
- **Multi-tabbed GUI**: Capture, Analysis, Security, and Monitoring tabs
- **Interactive Charts**: Real-time updating visualizations with matplotlib
- **Advanced Packet Display**: Detailed packet information with protocol detection
- **Security Dashboard**: Dedicated security monitoring and alerting interface

### ⚡ Performance & Usability
- **Flexible Filtering**: Advanced BPF filter support
- **PCAP Export**: Save captures for further analysis
- **Cross-platform Compatibility**: Windows, Linux, macOS
- **Command-line & GUI**: Both interfaces for different use cases

## 🧰 Requirements

- Python 3.7 or higher
- Scapy library
- Matplotlib (for GUI visualizations)
- Npcap/WinPcap (for Windows packet capture)
- Administrator/root privileges (for packet capture)

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/CodeAlpha_NetworkSniffer.git
   cd CodeAlpha_NetworkSniffer
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Npcap (Windows users):**
   - Download from [https://npcap.com/#download](https://npcap.com/#download)
   - Run installer as Administrator
   - Restart computer after installation

3. **Run with administrator privileges:**
   - **Windows**: Run Command Prompt or PowerShell as Administrator
   - **Linux/macOS**: Use `sudo` or run as root

## 🚀 Usage

### Command Line Interface

#### Basic Usage
```bash
# Capture 20 packets on default interface
python enhanced_sniffer.py -c 20

# Capture TCP packets only with verbose output
python enhanced_sniffer.py -f "tcp" -c 50 -v

# Capture UDP packets on port 53 (DNS)
python enhanced_sniffer.py -f "udp port 53" -c 100

# Capture all traffic on specific interface
python enhanced_sniffer.py -i "Wi-Fi" -c 0

# Save captured packets to PCAP file with security analysis
python enhanced_sniffer.py -c 100 -s "capture.pcap" -v

# List available interfaces
python enhanced_sniffer.py -l

# Run the comprehensive demo
python demo_enhanced_sniffer.py
```

#### Advanced Filtering Examples
```bash
# HTTP traffic (port 80)
python sniffer.py -f "tcp port 80"

# HTTPS traffic (port 443)
python sniffer.py -f "tcp port 443"

# Traffic from specific IP
python sniffer.py -f "host 192.168.1.1"

# Traffic between two hosts
python sniffer.py -f "host 192.168.1.1 and host 192.168.1.2"

# Exclude broadcast traffic
python sniffer.py -f "not broadcast"

# ICMP packets (ping)
python sniffer.py -f "icmp"
```

### Enhanced Graphical User Interface

Launch the enhanced GUI version for a comprehensive interactive experience:

```bash
python enhanced_gui.py
```

**Enhanced GUI Features:**
- **Multi-tabbed Interface**: Capture, Analysis, Security, and Monitoring tabs
- **Real-time Protocol Detection**: Instant protocol identification and display
- **Interactive Charts**: Live-updating visualizations with matplotlib
- **Security Dashboard**: Dedicated security monitoring and alerting
- **Advanced Packet Analysis**: Detailed packet information with protocol detection
- **Real-time Statistics**: Protocol distribution, top talkers, port analysis
- **Security Alerts**: Real-time threat detection and notification
- **Monitoring Console**: Live network activity monitoring
- **Export Capabilities**: PCAP, statistics, and custom exports

## 📊 Output Examples

### Command Line Output
```
[*] Starting Network Sniffer...
[*] Interface: Default
[*] Filter: tcp
[*] Count: 10
[*] Timeout: None seconds
[*] Save to file: No
============================================================

[+] Packet #1
    Time: 2024-01-15T14:30:25.123456
    Protocol: TCP
    Source: 192.168.1.100
    Destination: 8.8.8.8
    Ports: 54321 -> 443
    Size: 60 bytes
    Payload: <20 bytes>
------------------------------------------------------------

[+] Packet #2
    Time: 2024-01-15T14:30:25.234567
    Protocol: TCP
    Source: 8.8.8.8
    Destination: 192.168.1.100
    Ports: 443 -> 54321
    Size: 52 bytes
    Payload: No payload
------------------------------------------------------------
```

### GUI Screenshots

The GUI provides a clean, organized view of captured packets with:
- **Control Panel**: Interface selection, filters, and controls
- **Statistics**: Real-time packet counts by protocol
- **Packet Table**: Detailed packet information in sortable columns
- **Details Panel**: Raw packet data and analysis

## 🔧 Configuration Options

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-i, --interface` | Network interface to use | `-i "Wi-Fi"` |
| `-f, --filter` | BPF filter string | `-f "tcp port 80"` |
| `-c, --count` | Number of packets to capture | `-c 100` |
| `-t, --timeout` | Timeout in seconds | `-t 30` |
| `-s, --save` | Save to PCAP file | `-s "capture.pcap"` |
| `-l, --list-interfaces` | List available interfaces | `-l` |

### BPF Filter Examples

| Filter | Description |
|--------|-------------|
| `tcp` | TCP packets only |
| `udp` | UDP packets only |
| `icmp` | ICMP packets only |
| `port 80` | Traffic on port 80 |
| `host 192.168.1.1` | Traffic to/from specific IP |
| `src host 192.168.1.1` | Traffic from specific IP |
| `dst host 192.168.1.1` | Traffic to specific IP |
| `net 192.168.1.0/24` | Traffic in specific network |
| `not broadcast` | Exclude broadcast traffic |

## 📁 Project Structure

```
CodeAlpha_NetworkSniffer/
├── enhanced_sniffer.py      # Enhanced command-line sniffer with security analysis
├── enhanced_gui.py          # Advanced GUI with multi-tabbed interface
├── protocol_detector.py     # Comprehensive protocol detection engine
├── sniffer.py              # Basic command-line network sniffer
├── sniffer_gui.py          # Basic GUI version
├── demo_enhanced_sniffer.py # Comprehensive feature demonstration
├── test_installation.py    # Installation verification script
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── screenshots/           # GUI screenshots and examples
└── examples/              # Example captures and scripts
    ├── simple_sniffer.py   # Basic sniffer example
    └── advanced_sniffer.py # Advanced protocol analysis example
```

## 🛠️ Development

### Adding New Features

1. **Protocol Decoders**: Add support for specific protocols (HTTP, DNS, etc.)
2. **Advanced Filters**: Implement custom filter functions
3. **Export Formats**: Add JSON, CSV, or XML export options
4. **Real-time Analysis**: Add traffic pattern detection
5. **Network Mapping**: Visualize network topology

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## ⚠️ Important Notes

### Security and Legal Considerations

- **Administrator privileges required**: Packet capture requires elevated permissions
- **Legal compliance**: Only capture traffic on networks you own or have permission to monitor
- **Privacy**: Be mindful of sensitive data in packet payloads
- **Network impact**: High-volume capture may affect network performance

### Troubleshooting

**Common Issues:**

1. **Permission Denied**: Run as administrator/root
2. **No packets captured**: Check interface name and network connectivity
3. **Scapy import error**: Ensure Scapy is properly installed
4. **Filter syntax error**: Verify BPF filter syntax

**Debug Mode:**
```bash
# Enable verbose output
python sniffer.py -c 10 --debug
```

## 📚 Additional Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [BPF Filter Syntax](https://biot.com/capstats/bpf.html)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Network Protocol Analysis](https://en.wikipedia.org/wiki/Network_protocol_analysis)

## 📄 Disclaimer

 Intended solely for ethical security testing and research. Unauthorized use may violate laws and organizational policies. Users are responsible for ensuring compliance with all applicable legal and ethical standards.

## 🤝 Acknowledgments

- Scapy development team for the excellent packet manipulation library
- Wireshark team for inspiration and PCAP format support
- Python community for the robust ecosystem

---

**Happy Network Sniffing! 🕵️‍♂️** 