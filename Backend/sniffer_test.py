from scapy.all import sniff

def packet_callback(packet):

    print(packet.summary())

print("Sniffing packets...")

sniff(
    prn=packet_callback,
    store=False,
    count=10
)