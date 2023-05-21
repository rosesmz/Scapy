from scapy.all import *
from scapy.layers.inet import TCP

def packet_handler(packet):
    if packet.haslayer(TCP):
        tcp = packet.getlayer(TCP)
        if tcp.dport == 80 or tcp.sport == 80:
            http_payload = str(packet[TCP].payload)
            if http_payload.startswith('GET') or http_payload.startswith('POST'):
                print("HTTP packet detected")
                print("Payload:\n", http_payload)

# Sniff packets on the network interface
sniff(filter="", prn=packet_handler)