# Advanced Packet Sniffer

A professional network monitoring tool with real-time web interface, PCAP export, and security alert system.

## Features

- **Real-time Web Interface** - Live packet monitoring via browser
- **PCAP Export** - Save captures for Wireshark analysis  
- **Security Alerts** - Automatic threat detection
- **Live Search** - Filter packets in real-time
- **Statistics** - Protocol breakdown and traffic analysis
- **Multi-threaded** - High-performance packet processing

Project Structure

advanced-packet-sniffer/
├── packet_sniffer.py    # Main web interface version
├── mini_sniffer.py      # CLI version
├── advanced_sniffer.py  # Enhanced version with alerts
├── captures/            # PCAP files directory
├── DEMO_GUIDE.txt      # Faculty demonstration guide
├── requirements.txt     # Dependencies
├── README.md           # This file
├── .gitignore          # Python gitignore
└── LICENSE             # MIT License


Security Features

Port Scan Detection - Alerts on suspicious connection patterns
Traffic Monitoring - Real-time network analysis
Forensic Export - PCAP files for Wireshark analysis
Live Alerts - Immediate threat notifications
## Quick Start

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/advanced-packet-sniffer.git
cd advanced-packet-sniffer

# Install dependencies
pip install scapy

# Run the sniffer (requires Linux and root privileges)
sudo python3 packet_sniffer.py

Then open: http://localhost:8000

Demo Instructions

1. Start the application:
sudo python3 packet_sniffer.py

2. Access web interface:
3. Open browser to http://localhost:8000
  View real-time packet statistics

4. Record traffic:
  Click "Start PCAP" to begin recording
  Generate network traffic
  Click "Stop PCAP" to save file

5. Monitor security:
   Watch for automatic security alerts
   Use search to filter specific packets
   Analyze protocol breakdown


Requirements

Python 3.6+
Scapy (pip install scapy)
Linux environment (Kali Linux recommended)
Root privileges (for packet capture)
