#!/usr/bin/env python3
import argparse
import json
import time
import threading
from collections import defaultdict
from scapy.all import sniff, PcapWriter, IP, TCP, UDP, ICMP, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.record import TLS
from cryptography import x509
from cryptography.hazmat.primitives import serialization

class Sniffer:
    def __init__(self, iface=None, bpf=None, count=0, duration=0, outfile=None, jsonfile=None, promiscuous=False):
        self.iface = iface
        self.bpf = bpf
        self.count = count
        self.duration = duration
        self.outfile = outfile
        self.jsonfile = jsonfile
        self.promiscuous = promiscuous
        self.pwriter = PcapWriter(outfile, append=True, sync=True) if outfile else None
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.packet_count = 0
        self.stats = {"by_proto": defaultdict(int), "flows": {}, "hosts": defaultdict(int)}
    def _flow_key(self, pkt):
        try:
            ip = pkt[IP]
            if TCP in pkt:
                t = pkt[TCP]
                return f"{ip.src}:{t.sport}-{ip.dst}:{t.dport}-TCP"
            if UDP in pkt:
                u = pkt[UDP]
                return f"{ip.src}:{u.sport}-{ip.dst}:{u.dport}-UDP"
            return f"{ip.src}-{ip.dst}-{pkt.proto}"
        except Exception:
            return "unknown"
    def _extract_http(self, pkt):
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            host = req.Host.decode() if isinstance(req.Host, bytes) else req.Host
            path = req.Path.decode() if isinstance(req.Path, bytes) else req.Path
            return {"http_host": host, "http_path": path}
        return {}
    def _extract_tls_sni(self, pkt):
        try:
            if pkt.haslayer(TLS):
                for layer in pkt.layers():
                    if layer.__name__ == "TLSClientHello":
                        raw = bytes(pkt)
                        if b"\x00\x00" in raw:
                            return {}
            raw = bytes(pkt)
            idx = raw.find(b"\x00\x00\x00")
            return {}
        except Exception:
            return {}
    def _pkt_summary(self, pkt):
        s = {}
        if IP in pkt:
            ip = pkt[IP]
            s["src"] = ip.src
            s["dst"] = ip.dst
            proto = None
            if TCP in pkt:
                proto = "TCP"
                tcp = pkt[TCP]
                s["sport"] = tcp.sport
                s["dport"] = tcp.dport
            elif UDP in pkt:
                proto = "UDP"
                udp = pkt[UDP]
                s["sport"] = udp.sport
                s["dport"] = udp.dport
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                proto = str(ip.proto)
            s["proto"] = proto
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            try:
                s["payload_preview"] = payload[:80].hex()
            except Exception:
                s["payload_preview"] = str(payload)[:80]
        s.update(self._extract_http(pkt))
        s.update(self._extract_tls_sni(pkt))
        return s
    def _count_proto(self, proto):
        with self.lock:
            self.stats["by_proto"][proto] += 1
    def _record_flow(self, key, pkt):
        with self.lock:
            f = self.stats["flows"].setdefault(key, {"pkts":0,"bytes":0,"first":time.time(),"last":time.time()})
            f["pkts"] += 1
            f["bytes"] += len(bytes(pkt))
            f["last"] = time.time()
    def _record_host(self, host):
        with self.lock:
            self.stats["hosts"][host] += 1
    def _handle(self, pkt):
        self.packet_count += 1
        if self.pwriter:
            try:
                self.pwriter.write(pkt)
            except Exception:
                pass
        proto = "OTHER"
        if IP in pkt:
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
        self._count_proto(proto)
        try:
            if IP in pkt:
                self._record_host(pkt[IP].src)
                self._record_host(pkt[IP].dst)
                key = self._flow_key(pkt)
                self._record_flow(key, pkt)
        except Exception:
            pass
        summary = self._pkt_summary(pkt)
        print(f"{self.packet_count:6d} {summary.get('proto','?'):4s} {summary.get('src','-')}:{summary.get('sport','-')} -> {summary.get('dst','-')}:{summary.get('dport','-')}", end="")
        if "http_host" in summary:
            print(f" HTTP {summary.get('http_host')}{summary.get('http_path')}", end="")
        print()
    def start(self):
        kwargs = {}
        if self.iface:
            kwargs["iface"] = self.iface
        if self.bpf:
            kwargs["filter"] = self.bpf
        if self.promiscuous:
            kwargs["promisc"] = True
        if self.count > 0:
            kwargs["count"] = self.count
        if self.duration > 0:
            t = threading.Thread(target=self._stop_after_duration)
            t.daemon = True
            t.start()
        sniff(prn=self._handle, store=False, **kwargs)
        self._finish()
    def _stop_after_duration(self):
        time.sleep(self.duration)
        raise SystemExit
    def _finish(self):
        if self.jsonfile:
            export = {"captured": self.packet_count, "duration_seconds": time.time()-self.start_time, "by_proto": dict(self.stats["by_proto"]), "top_hosts": sorted(self.stats["hosts"].items(), key=lambda x:x[1], reverse=True)[:20], "flows_count": len(self.stats["flows"])}
            with open(self.jsonfile, "w") as f:
                json.dump(export, f, indent=2)
        if self.pwriter:
            try:
                self.pwriter.close()
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", "-i", help="interface")
    parser.add_argument("--filter", "-f", help="BPF filter")
    parser.add_argument("--count", "-c", type=int, default=0, help="packet count")
    parser.add_argument("--duration", "-d", type=int, default=0, help="seconds to run")
    parser.add_argument("--outfile", "-o", help="pcap output file")
    parser.add_argument("--json", "-j", dest="jsonfile", help="json summary output")
    parser.add_argument("--promiscuous", action="store_true")
    args = parser.parse_args()
    s = Sniffer(iface=args.iface, bpf=args.filter, count=args.count, duration=args.duration, outfile=args.outfile, jsonfile=args.jsonfile, promiscuous=args.promiscuous)
    try:
        s.start()
    except KeyboardInterrupt:
        s._finish()

if __name__ == "__main__":
    main()
