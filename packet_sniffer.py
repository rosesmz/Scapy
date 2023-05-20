from scapy.all import *
from scapy.layers.http import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from scapy.layers.http import HTTP
import tkinter as tk
from tkinter import *
import tkinter.ttk as ttk
import customtkinter as ctk
from PIL import Image
import time
from datetime import datetime

was_stopped = False

class Sniffer:
    def __init__(self, output_box):
        self.is_running = False
        self.output_box = output_box
        self.sniffer = None
    
    def setup_sniffer(self):
        protocols = ['tcp','udp','http','icmp','arp','dns']
        filter = getinput().lower()
        if filter == 'http':
            self.sniffer = AsyncSniffer(filter='tcp port 80', prn= add_packet)
        elif filter == 'dns':
            self.sniffer = AsyncSniffer(filter='tcp port 53 or udp port 53', prn= add_packet)
        elif filter not in protocols:
            msg = tk.messagebox.showerror("Error", "Specified filter doesn't exist!\nRunning all protocols.")
            self.sniffer = AsyncSniffer(filter='', prn= add_packet)
        else:
            self.sniffer = AsyncSniffer(filter=filter, prn= add_packet)

    def start(self):
        global start_time
        self.is_running = True
        self.sniffer.start()
        start_time = datetime.now()
    
    def stop(self):
        global was_stopped
        if execution_time > 0.5:
            if self.is_running:
                was_stopped = True
                self.sniffer.stop()
                self.is_running = False


def start_sniffing():
    main_sniffer.setup_sniffer()
    
    main_sniffer.start()

def stop_sniffing():
    main_sniffer.stop()

def get_protocol(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    elif DNS in packet:
        return "DNS"
    elif ARP in packet:
        return "ARP"
    elif HTTP in packet:
        return "HTTP"
    else:
        return "Other"

packet_number = 1
is_first = True
execution_time = 0.0
time_diff_converted = 0.0
start_time = datetime.now()
def add_packet(packet):

    global packet_number, start_time, execution_time, was_stopped
    end_time = datetime.now()

    if was_stopped:
        time_diff_converted = 0.0
        was_stopped = False       
    else:
        time_diff = (end_time - start_time)
        time_diff_converted = time_diff.total_seconds()
    execution_time += time_diff_converted

    if HTTPRequest in packet or HTTPResponse in packet:
        table.insert(parent='',index='end',iid=packet_number,text='',
        values=(packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, 'HTTP', len(packet), packet.summary()))
    elif DNS in packet:
        table.insert(parent='',index='end',iid=packet_number,text='',
        values=(packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, 'DNS', len(packet), packet.summary()))
    elif ARP in packet:
        table.insert(parent='',index='end',iid=packet_number,text='',
        values=(packet_number, round(execution_time, 6), packet[ARP].hwsrc, packet[ARP].hwdst, 'ARP', len(packet), packet.summary()))        
    elif IP in packet:    
        table.insert(parent='',index='end',iid=packet_number,text='',
        values=(packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, get_protocol(packet), len(packet), packet.summary()))
        
    packet_number +=1
    start_time = datetime.now()

# def packet_sniff():
#     filter = getinput()
#     sniffer = AsyncSniffer(filter=filter, prn= lambda packet: output.insert(END, packet.summary() + "\n"))
#     sniffer.start()

#     output.bind("<Control - c>", lambda event: sniffer.stop())

def packet_callback(packet):
    print(packet.summary())
    return packet.summary()
    
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


if __name__ == '__main__':
    # main()
    # interfaces = get_if_list()
    # s = threading.Thread(target=packet_sniff)
    # s.start()

    # style = ttk.Style()
    
    # style.theme_use("default")

    # style.configure("Treeview",
    #                 background="#2a2d2e",
    #                 foreground="white",
    #                 rowheight=25,
    #                 fieldbackground="#343638",
    #                 bordercolor="#343638",
    #                 borderwidth=0)
    
    # style.map('Treeview', background=[('selected', '#22559b')])

    # style.configure("Treeview.Heading",
    #                 background="#565b5e",
    #                 foreground="white",
    #                 relief="flat")
    
    # style.map("Treeview.Heading",
    #             background=[('active', '#3484F0')])

    root = ctk.CTk()
    root.title("Packet Sniffer")
    root.iconbitmap(r"Images\nose.ico")
    root.geometry("750x550")

    style = ttk.Style()
    style.theme_use("default")
    style.configure("Treeview",
                    background="#2c2c2c",
                    foreground="white",
                    rowheight=25,
                    fieldbackground="#2c2c2c",
                    bordercolor="#343638",
                    borderwidth=0)
    
    style.map('Treeview', background=[('selected', '#22559b')])
    style.configure("Treeview.Heading",
                background="#565b5e",
                foreground="white",
                relief="flat")
    style.map("Treeview.Heading",
        background=[('active', '#212121')])

    start_img = ctk.CTkImage(light_image=Image.open(r"Images\play.png"), size=(20,20))
    stop_img = ctk.CTkImage(light_image=Image.open(r"Images\stop.png"), size=(20,20))

    def getinput():
        global filter_input
        filter = filter_input.get()
        return filter

    upper_frame = ctk.CTkFrame(root, corner_radius=10)
    upper_frame.pack(pady=20)

    filter_input = ctk.CTkEntry(upper_frame, width=500, height=40, border_width=1, placeholder_text="Enter filter to apply...", text_color="silver")
    filter_input.grid(row=0, column=0,padx=10,pady=10)

    start_button = ctk.CTkButton(upper_frame, image=start_img, text="", command=start_sniffing, width=20, height=35, fg_color="#212121", hover_color="#1c1c1c")
    start_button.grid(row=0, column=1, padx=5)

    stop_button = ctk.CTkButton(upper_frame, image=stop_img, text="", command=stop_sniffing, width=20, height=35, fg_color="#212121", hover_color="#1c1c1c")
    stop_button.grid(row=0, column=2, padx=5)

    output_frame = ctk.CTkFrame(root, corner_radius=10)
    output_frame.pack(pady=10)
    
    # def create_table():
    global table

    # y_scroll = Scrollbar(output_frame)
    # y_scroll.pack(side=RIGHT, fill=Y)

    # x_scroll = Scrollbar(output_frame, orient='horizontal')
    # x_scroll.pack(side= BOTTOM,fill=X)

    table = ttk.Treeview(output_frame)
 
    # y_scroll.config(command=table.yview)
    # x_scroll.config(command=table.xview)

    table = ttk.Treeview(output_frame)
    table['columns'] = ('packet_id', 'packet_time', 'packet_source', 'packet_destination', 'packet_protocol', 'packet_length','packet_info')

    table.column("#0", width=0, minwidth=25)
    table.column("packet_id",anchor=CENTER, width=80)
    table.column("packet_time",anchor=CENTER,width=80)
    table.column("packet_source",anchor=CENTER,width=80)
    table.column("packet_destination",anchor=CENTER,width=80)
    table.column("packet_protocol",anchor=CENTER,width=80)
    table.column("packet_length",anchor=CENTER,width=80)
    table.column("packet_info",anchor=CENTER,width=80)

    table.heading("#0",text="",anchor=CENTER)
    table.heading("packet_id",text="Id",anchor=CENTER)
    table.heading("packet_time",text="Time",anchor=CENTER)
    table.heading("packet_source",text="Source",anchor=CENTER)
    table.heading("packet_destination",text="Destination",anchor=CENTER)
    table.heading("packet_protocol",text="Protocol",anchor=CENTER)
    table.heading("packet_length",text="Length",anchor=CENTER)
    table.heading("packet_info",text="Packet",anchor=CENTER)

    table.pack()

    output = Text(output_frame, height=20, width=85, wrap=WORD, bd=0, bg="#2c2c2c", fg="silver", font=("Arial", 10))
    output.pack(padx=10, pady=10)

    main_sniffer = Sniffer(output_box=output)

    under_frame = ctk.CTkFrame(root, corner_radius=10)
    under_frame.pack(pady=10)

    # interfaces_list = show_interfaces()
    interfaces = ctk.CTkOptionMenu(under_frame, values=["Option 1", "Option 2", "Option 3"])
    interfaces.pack(padx=10, pady=10)
    interfaces.set("Choose an interface")

    map_button = ctk.CTkButton(under_frame, text="Open Map")
    map_button.pack(pady=10)

    root.mainloop()