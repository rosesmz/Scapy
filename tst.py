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

        packet_info = str(packet.show(dump=True))
        print(packet.summary())
        # treeview.insert("", tk.END, values=(packet_info, '', '', ''))

window = tk.Tk()
window.title("Packet Sniffer")
window.geometry("600x400")

table_frame = tk.Frame(window)
table_frame.pack(fill="both", expand=True)

treeview = ttk.Treeview(table_frame, columns=("source_ip", "dest_ip", "protocol", "length"), show="headings")
treeview.column("source_ip", width=150)
treeview.column("dest_ip", width=150)
treeview.column("protocol", width=100)
treeview.column("length", width=100)
treeview.heading("source_ip", text="Source IP")
treeview.heading("dest_ip", text="Destination IP")
treeview.heading("protocol", text="Protocol")
treeview.heading("length", text="Length")
treeview.pack(fill="both", expand=True)

sniff(prn=packet_handler, count=10)

window.mainloop()
