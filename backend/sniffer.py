"""
Scapy Packet Sniffer — Detection Engine
----------------------------------------
Captures live network traffic and inspects every packet for:
  1. TCP SYN floods / port scans
  2. ARP reply anomalies (spoofing)

Detected threats are scored by scorer.py and pushed to the
Flask alert store (app.py) for consumption by the dashboard
and ESP32.

Usage:
    sudo python sniffer.py          # Linux / macOS
    python sniffer.py               # Windows (run as admin)
"""

from scapy.all import sniff, ARP, TCP, IP, conf
from scorer import score_port_scan, score_arp_spoof
from app import add_alert, run_flask
import threading
import time
import sys
import logging

_log = logging.getLogger(__name__)

# Suppress Scapy IPv6 warning on Windows
conf.ipv6_enabled = False


def packet_handler(pkt):
    """Inspect a single captured packet for threats."""

    # ── TCP SYN Detection (Port Scan) ──────────────────────────────
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        tcp_layer = pkt[TCP]
        # SYN flag set, ACK not set → connection initiation probe
        if tcp_layer.flags == "S":
            src_ip = pkt[IP].src
            dst_port = tcp_layer.dport

            severity, count = score_port_scan(src_ip, dst_port)

            if severity:
                alert = {
                    "type": "PORT_SCAN",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "severity": severity,
                    "ports_per_5s": count,
                    "time": time.strftime("%H:%M:%S"),
                }
                add_alert(alert)
                _log.info("[%s] Port scan from %s — %s ports/5s", severity, src_ip, count)

    # ── ARP Reply Detection (Spoofing) ─────────────────────────────
    if pkt.haslayer(ARP):
        arp_layer = pkt[ARP]
        # op == 2 means ARP *reply*
        if arp_layer.op == 2:
            src_mac = arp_layer.hwsrc
            src_ip = arp_layer.psrc

            severity = score_arp_spoof(src_mac, src_ip)

            if severity:
                alert = {
                    "type": "ARP_SPOOFING",
                    "src_ip": src_ip,
                    "src_mac": src_mac,
                    "severity": severity,
                    "time": time.strftime("%H:%M:%S"),
                }
                add_alert(alert)
                _log.info("[%s] ARP spoofing detected from %s (%s)", severity, src_ip, src_mac)


def main():
    # Start Flask API in a background thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    _log.info("Sniffer Active")
    _log.info("Flask API running on http://0.0.0.0:5000")
    _log.info("Listening for TCP SYN probes & ARP anomalies")

    try:
        sniff(
            filter="tcp or arp",
            prn=packet_handler,
            store=0,        # don't store packets in memory
        )
    except PermissionError:
        _log.error("Permission denied -- run with sudo (Linux) or as Admin (Windows)")
        sys.exit(1)
    except KeyboardInterrupt:
        _log.info("Sniffer stopped.")


if __name__ == "__main__":
    main()
