from scapy.all import sniff
from scapy.layers.inet import IP, TCP, ICMP
import requests
import time
import threading
import subprocess

BACKEND_URL = "https://your-render-url.onrender.com/api/add-log"

# ====================================
# Config
# ====================================

THRESHOLD = 20

WHITELIST = {
    "127.0.0.1",
    "192.168.1.1"
}

# ====================================
# Runtime Memory
# ====================================

ip_counter = {}
blocked_ips = set()
last_reset = time.time()

# ====================================
# Send Logs
# ====================================

def send_log(log_type, message):

    payload = {

        "type": log_type,
        "log": message,
        "timestamp": time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }

    try:

        requests.post(
            BACKEND_URL,
            json=payload,
            timeout=1
        )

    except Exception as e:

        print(
            "[ERROR]",
            e
        )

# ====================================
# Firewall Block
# ====================================

def block_ip(ip):

    if ip in blocked_ips:

        return

    blocked_ips.add(ip)

    print(
        f"[IPS] Blocking IP: {ip}"
    )

    # WINDOWS

    subprocess.run([
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name=GuardianNode_Block_{ip}",
        "dir=in",
        "action=block",
        f"remoteip={ip}"
    ])

    send_log(
        "CRITICAL",
        f"IP BLOCKED → {ip}"
    )

# ====================================
# Reset Counters
# ====================================

def reset_counters():

    global ip_counter
    global last_reset

    while True:

        time.sleep(60)

        ip_counter.clear()

        last_reset = time.time()

        print(
            "[INFO] Counters Reset"
        )

# ====================================
# Threat Detection
# ====================================

def detect_threat(packet):

    if not packet.haslayer(IP):

        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Ignore whitelist

    if src_ip in WHITELIST:

        return

    # Ignore blocked

    if src_ip in blocked_ips:

        return

    # ====================================
    # Count Packets
    # ====================================

    ip_counter[src_ip] = (
        ip_counter.get(src_ip, 0) + 1
    )

    packet_count = ip_counter[src_ip]

    # ====================================
    # SYN FLOOD DETECTION
    # ====================================

    if packet.haslayer(TCP):

        flags = packet[TCP].flags

        if flags == "S":

            log = (
                f"[SYN] "
                f"{src_ip} → {dst_ip}"
            )

            print(log)

            send_log(
                "WARNING",
                log
            )

    # ====================================
    # ICMP FLOOD DETECTION
    # ====================================

    if packet.haslayer(ICMP):

        log = (
            f"[ICMP] "
            f"{src_ip} → {dst_ip}"
        )

        print(log)

        send_log(
            "WARNING",
            log
        )

    # ====================================
    # THRESHOLD DETECTION
    # ====================================

    if packet_count > THRESHOLD:

        block_ip(src_ip)

        return

    # ====================================
    # Normal Packet
    # ====================================

    log = (
        f"[PACKET] "
        f"{src_ip} → {dst_ip}"
    )

    print(log)

# ====================================
# Start Threads
# ====================================

threading.Thread(
    target=reset_counters,
    daemon=True
).start()

# ====================================
# Start Sniffer
# ====================================

print(
    "GuardianNode IDS + IPS Running..."
)

sniff(
    prn=detect_threat,
    store=False
)