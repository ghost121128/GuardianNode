from scapy.all import sniff
from scapy.layers.inet import IP

import requests
import time

BACKEND_URL = "https://your-render-url.onrender.com/api/add-log"

# ====================================
# Track IP Requests
# ====================================

ip_counter = {}

# ====================================
# Blocked IPs
# ====================================

blocked_ips = set()

# ====================================
# Detection Threshold
# ====================================

THRESHOLD = 15

# ====================================
# Process Packets
# ====================================

def process_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Skip blocked IPs
        if src_ip in blocked_ips:

            return

        # Count packets
        if src_ip not in ip_counter:

            ip_counter[src_ip] = 1

        else:

            ip_counter[src_ip] += 1

        # ====================================
        # Threat Detection
        # ====================================

        if ip_counter[src_ip] > THRESHOLD:

            blocked_ips.add(src_ip)

            threat_log = f"[CRITICAL] IP BLOCKED → {src_ip}"

            print(threat_log)

            try:

                requests.post(

                    BACKEND_URL,

                    json={

                        "log": threat_log

                    }

                )

            except Exception as e:

                print(e)

            return

        # ====================================
        # Normal Traffic
        # ====================================

        log = f"[PACKET] {src_ip} → {dst_ip}"

        print(log)

        try:

            requests.post(

                BACKEND_URL,

                json={

                    "log": log

                }

            )

        except Exception as e:

            print(e)

# ====================================
# Start Sniffer
# ====================================

print(
    "GuardianNode IDS + IPS Running..."
)

sniff(

    prn=process_packet,

    store=False

)