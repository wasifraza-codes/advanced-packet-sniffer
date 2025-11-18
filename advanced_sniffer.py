#!/usr/bin/env python3
import http.server
import socketserver
import threading
import time
import json
import re
from scapy.all import sniff, IP, TCP, UDP, Raw, PcapWriter
from collections import deque

class PacketSniffer:
    def __init__(self):
        self.stats = {
            "packet_count": 0,
            "start_time": time.time(),
            "by_protocol": {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0},
            "recent_packets": deque(maxlen=100),
            "alerts": deque(maxlen=50),
            "pcap_writer": None,
            "pcap_filename": None
        }
        self.search_filter = ""
        self.alerts_enabled = True
        
        # Alert rules
        self.alert_rules = [
            {"name": "Port Scan", "pattern": "sport.*>1024.*dport.*<1024", "type": "suspicious"},
            {"name": "DNS to Unknown", "pattern": "dport.*53", "type": "info"},
            {"name": "Multiple SYN", "pattern": "flags.*S", "type": "warning"},
            {"name": "HTTP Traffic", "pattern": "dport.*80", "type": "info"}
        ]
    
    def add_alert(self, message, alert_type="info"):
        alert = {
            "time": time.strftime("%H:%M:%S"),
            "message": message,
            "type": alert_type
        }
        self.stats["alerts"].appendleft(alert)
        print(f"🚨 ALERT [{alert_type}]: {message}")
    
    def check_alerts(self, packet_info):
        if not self.alerts_enabled:
            return
            
        packet_str = f"{packet_info['src']}:{packet_info['sport']} -> {packet_info['dst']}:{packet_info['dport']} {packet_info['protocol']}"
        
        # Check for port scans (multiple connections from same source)
        if packet_info['protocol'] == 'TCP':
            recent_from_src = [p for p in list(self.stats["recent_packets"])[:10] 
                             if p['src'] == packet_info['src'] and p['protocol'] == 'TCP']
            if len(recent_from_src) > 5:
                self.add_alert(f"Possible port scan from {packet_info['src']}", "warning")
        
        # Check DNS queries to non-standard servers
        if packet_info['dport'] == 53 and not any(server in packet_info['dst'] for server in ['8.8.8.8', '1.1.1.1', '192.168']):
            self.add_alert(f"DNS query to unusual server: {packet_info['dst']}", "suspicious")
    
    def extract_http(self, packet):
        try:
            if TCP in packet and packet[TCP].dport == 80 and Raw in packet:
                raw = packet[Raw].load
                if b'GET' in raw or b'POST' in raw:
                    lines = raw.split(b'\r\n')
                    host = path = ""
                    for line in lines:
                        if line.startswith(b'Host:'):
                            host = line.split(b': ')[1].decode()
                        if line.startswith(b'GET') or line.startswith(b'POST'):
                            path = line.split(b' ')[1].decode()
                    return f"{host}{path}" if host else "HTTP Request"
        except:
            pass
        return None
    
    def start_pcap_capture(self, filename):
        self.stats["pcap_filename"] = filename
        self.stats["pcap_writer"] = PcapWriter(filename, append=True, sync=True)
        self.add_alert(f"Started PCAP capture: {filename}", "info")
    
    def stop_pcap_capture(self):
        if self.stats["pcap_writer"]:
            self.stats["pcap_writer"].close()
            self.add_alert(f"Stopped PCAP capture: {self.stats['pcap_filename']}", "info")
            self.stats["pcap_writer"] = None
            self.stats["pcap_filename"] = None
    
    def handle_packet(self, packet):
        self.stats["packet_count"] += 1
        info = {"time": time.strftime("%H:%M:%S"), "id": self.stats["packet_count"]}
        
        try:
            if IP in packet:
                ip = packet[IP]
                info["src"] = ip.src
                info["dst"] = ip.dst
                
                if TCP in packet:
                    info["protocol"] = "TCP"
                    tcp = packet[TCP]
                    info["sport"] = tcp.sport
                    info["dport"] = tcp.dport
                    info["flags"] = str(tcp.flags)
                    self.stats["by_protocol"]["TCP"] += 1
                    
                    http_info = self.extract_http(packet)
                    if http_info:
                        info["http"] = http_info
                        
                elif UDP in packet:
                    info["protocol"] = "UDP"
                    udp = packet[UDP]
                    info["sport"] = udp.sport
                    info["dport"] = udp.dport
                    self.stats["by_protocol"]["UDP"] += 1
                else:
                    info["protocol"] = "OTHER"
                    self.stats["by_protocol"]["OTHER"] += 1
                
                # Save to PCAP if enabled
                if self.stats["pcap_writer"]:
                    self.stats["pcap_writer"].write(packet)
                
                # Check alerts
                self.check_alerts(info)
                
                # Apply search filter
                if not self.search_filter or self.search_filter.lower() in str(info).lower():
                    self.stats["recent_packets"].appendleft(info)
                
        except Exception as e:
            pass

    def start(self):
        threading.Thread(target=lambda: sniff(prn=self.handle_packet, store=False), daemon=True).start()

class WebHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/data':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            data = {
                "packet_count": sniffer.stats["packet_count"],
                "running_time": round(time.time() - sniffer.stats["start_time"], 2),
                "by_protocol": sniffer.stats["by_protocol"],
                "recent_packets": list(sniffer.stats["recent_packets"]),
                "alerts": list(sniffer.stats["alerts"]),
                "pcap_capturing": sniffer.stats["pcap_filename"] is not None,
                "pcap_filename": sniffer.stats["pcap_filename"] or ""
            }
            self.wfile.write(json.dumps(data).encode())
        
        elif self.path.startswith('/control/'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            command = self.path.split('/')[-1]
            response = {"status": "unknown_command"}
            
            if command == 'start_pcap':
                filename = f"capture_{int(time.time())}.pcap"
                sniffer.start_pcap_capture(filename)
                response = {"status": "started", "filename": filename}
            elif command == 'stop_pcap':
                sniffer.stop_pcap_capture()
                response = {"status": "stopped"}
            elif command == 'clear_alerts':
                sniffer.stats["alerts"].clear()
                response = {"status": "cleared"}
            elif command == 'toggle_alerts':
                sniffer.alerts_enabled = not sniffer.alerts_enabled
                response = {"status": "toggled", "alerts_enabled": sniffer.alerts_enabled}
            
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path.startswith('/search/'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            search_term = self.path.split('/')[-1]
            sniffer.search_filter = search_term
            response = {"status": "search_updated", "term": search_term}
            self.wfile.write(json.dumps(response).encode())
        
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = '''
            <html>
            <head><title>Advanced Packet Sniffer</title>
            <style>
                body{font-family:Arial;margin:20px;background:#f0f0f0}
                .panel{background:white;padding:15px;margin:10px 0;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
                .packet{margin:5px 0;padding:8px;background:#f5f5f5;border-radius:4px}
                .tcp{border-left:4px solid blue}
                .udp{border-left:4px solid red}
                .http{background:#e8f4fd}
                .alert-info{color:#31708f;background:#d9edf7;border:1px solid #bce8f1}
                .alert-warning{color:#8a6d3b;background:#fcf8e3;border:1px solid #faebcc}
                .alert-suspicious{color:#a94442;background:#f2dede;border:1px solid #ebccd1}
                .controls{display:flex;gap:10px;margin:10px 0}
                button{padding:8px 15px;border:none;border-radius:4px;cursor:pointer}
                .btn-start{background:#5cb85c;color:white}
                .btn-stop{background:#d9534f;color:white}
                .btn-clear{background:#f0ad4e;color:white}
                input[type="text"]{padding:8px;border:1px solid #ddd;border-radius:4px;flex-grow:1}
            </style>
            </head>
            <body>
                <h1>🚀 Advanced Packet Sniffer</h1>
                
                <div class="panel">
                    <h3>📊 Statistics</h3>
                    <div id="stats">
                        <p>Packets: <strong id="count">0</strong> | 
                        TCP: <strong id="tcp">0</strong> | 
                        UDP: <strong id="udp">0</strong> |
                        Running: <strong id="runtime">0</strong>s</p>
                    </div>
                </div>

                <div class="panel">
                    <h3>🎛️ Controls</h3>
                    <div class="controls">
                        <button class="btn-start" onclick="control('start_pcap')">📁 Start PCAP</button>
                        <button class="btn-stop" onclick="control('stop_pcap')">⏹️ Stop PCAP</button>
                        <button class="btn-clear" onclick="control('clear_alerts')">🗑️ Clear Alerts</button>
                        <button onclick="control('toggle_alerts')" id="toggleAlerts">🔔 Alerts: ON</button>
                        <input type="text" id="searchInput" placeholder="🔍 Search packets..." onkeyup="search(this.value)">
                    </div>
                    <div id="pcapStatus">PCAP: Not recording</div>
                </div>

                <div class="panel">
                    <h3>🚨 Security Alerts</h3>
                    <div id="alerts"></div>
                </div>

                <div class="panel">
                    <h3>📦 Live Packets</h3>
                    <div id="packets"></div>
                </div>

                <script>
                    let alertsEnabled = true;
                    
                    function control(command) {
                        fetch('/control/' + command)
                            .then(r => r.json())
                            .then(data => {
                                if(command === 'toggle_alerts') {
                                    alertsEnabled = data.alerts_enabled;
                                    document.getElementById('toggleAlerts').textContent = 
                                        '🔔 Alerts: ' + (alertsEnabled ? 'ON' : 'OFF');
                                }
                                updateData();
                            });
                    }
                    
                    function search(term) {
                        if(term.length > 2 || term.length === 0) {
                            fetch('/search/' + encodeURIComponent(term))
                                .then(r => r.json())
                                .then(updateData);
                        }
                    }
                    
                    function updateData() {
                        fetch('/data')
                            .then(r => r.json())
                            .then(data => {
                                // Update stats
                                document.getElementById('count').textContent = data.packet_count;
                                document.getElementById('tcp').textContent = data.by_protocol.TCP;
                                document.getElementById('udp').textContent = data.by_protocol.UDP;
                                document.getElementById('runtime').textContent = data.running_time;
                                
                                // Update PCAP status
                                document.getElementById('pcapStatus').innerHTML = 
                                    data.pcap_capturing ? 
                                    `📹 <strong>Recording:</strong> ${data.pcap_filename}` : 
                                    '📁 PCAP: Not recording';
                                
                                // Update alerts
                                document.getElementById('alerts').innerHTML = data.alerts.map(alert => 
                                    `<div class="packet alert-${alert.type}">
                                        <strong>${alert.time}</strong> ${alert.message}
                                    </div>`
                                ).join('');
                                
                                // Update packets
                                document.getElementById('packets').innerHTML = data.recent_packets.map(p => 
                                    `<div class="packet ${p.protocol.toLowerCase()} ${p.http?'http':''}">
                                        <strong>#${p.id}</strong> | ${p.protocol} | ${p.time} | 
                                        ${p.src}:${p.sport} → ${p.dst}:${p.dport}
                                        ${p.http?'<br>🌐 HTTP: '+p.http:''}
                                        ${p.flags?'<br>🚩 Flags: '+p.flags:''}
                                    </div>`
                                ).join('');
                            });
                    }
                    
                    setInterval(updateData, 1000);
                    updateData();
                </script>
            </body>
            </html>
            '''
            self.wfile.write(html.encode())

# Start everything
sniffer = PacketSniffer()
sniffer.start()

print("🚀 Advanced Packet Sniffer starting at http://localhost:8000")
print("📡 Features: PCAP capture, Search, Security Alerts, Live filtering")
print("🔧 Controls: Start/Stop PCAP, Clear alerts, Search packets")
with socketserver.TCPServer(("", 8000), WebHandler) as httpd:
    httpd.serve_forever()
