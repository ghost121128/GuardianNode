from scapy.all import sniff, IP, TCP
import datetime
from collections import defaultdict
import ml_model

LOG_FILE = "logs.txt"

normal_count = 0
alert_count = 0

time_labels = []
normal_series = []
alert_series = []

port_distribution = defaultdict(int)
ip_distribution = defaultdict(int)

MAX_POINTS = 20
suspicious_ports = [22, 23, 443]

def log_event(src, dst, status):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} | {src} -> {dst} | {status}\n")

def update_series():
    now = datetime.datetime.now().strftime("%H:%M:%S")
    time_labels.append(now)
    normal_series.append(normal_count)
    alert_series.append(alert_count)

    if len(time_labels) > MAX_POINTS:
        time_labels.pop(0)
        normal_series.pop(0)
        alert_series.pop(0)

def process_packet(packet):
    global normal_count, alert_count

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        size = len(packet)
        ml_result = ml_model.predict(size, 1)

        if packet.haslayer(TCP):
            dport = packet[TCP].dport

            if dport in suspicious_ports or ml_result == "ANOMALY":
                alert_count += 1
                port_distribution[dport] += 1
                ip_distribution[src] += 1
                log_event(src, dst, "ALERT: Threat Detected")
            else:
                normal_count += 1
                log_event(src, dst, "Normal Traffic")

            update_series()

def start_sniffing():
    sniff(prn=process_packet, store=False)