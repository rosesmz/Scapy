import socket
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_handler(packet):
    if Ether in packet:
        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"
        protocol = packet.proto if IP in packet else "N/A"
        length = len(packet) if IP in packet else "N/A"

        # treeview.insert("", tk.END, values=(src_ip, dst_ip, protocol, length))

# Sniff packets on the network interface
sniff(prn=packet_handler, count=10)


def run_client():
    host = 'localhost'
    port = 12345

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((host, port))
    print('Connected to server:', host, port)

    while True:
        # Send data to the server
        message = input("Enter a message (or 'quit' to exit): ")
        client_socket.send(message.encode('utf-8'))

        if message == 'quit':
            break

    # Close the connection
    client_socket.close()

run_client()