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
from datetime import datetime
import pickle
import socket


was_stopped = False

packet_list = []

class Sniffer:
    def __init__(self, output_box):
        self.is_running = False
        self.output_box = output_box
        self.sniffer = None
    
    def setup_sniffer(self):
        protocols = ['tcp','udp','http','icmp','arp','dns']
        filter = get_input().lower()
        if filter == 'http':
            self.sniffer = AsyncSniffer(filter='tcp port 80', prn=add_packet)
        elif filter == 'dns':
            self.sniffer = AsyncSniffer(filter='tcp port 53 or udp port 53', prn=add_packet)
        elif filter == '':
            self.sniffer = AsyncSniffer(filter='', prn=add_packet)
        elif filter.startswith("src") or filter.startswith("dst"):
            input = filter.split(":")
            self.sniffer = AsyncSniffer(filter=f'{input[0]} host {input[1]}', prn=add_packet)
        elif filter.startswith("port"):
            port = filter.split(":")[1]
            self.sniffer = AsyncSniffer(filter=f'port {port}', prn=add_packet)
        elif filter not in protocols:
            tk.messagebox.showerror("Error", "Specified filter doesn't exist!\nRunning all protocols.")
            self.sniffer = AsyncSniffer(filter='', prn=add_packet)
        else:
            self.sniffer = AsyncSniffer(filter=filter, prn=add_packet)

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
    packet_list.append(packet)

    if was_stopped:
        time_diff_converted = 0.0
        was_stopped = False       
    else:
        time_diff = (end_time - start_time)
        time_diff_converted = time_diff.total_seconds()
    execution_time += time_diff_converted


    values = ()
    try:
        if HTTPRequest in packet or HTTPResponse in packet:
            values=(packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, 'HTTP', len(packet), packet.summary())
        elif IP and DNS in packet:
            values=(packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, 'DNS', len(packet), packet.summary())
        elif ARP in packet:
            values=(packet_number, round(execution_time, 6), packet[ARP].hwsrc, packet[ARP].hwdst, 'ARP', len(packet), packet.summary())     
        elif IP in packet:    
            values=(packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, get_protocol(packet), len(packet), packet.summary())
    except:
        print("An exception occurred")

    if (values):
        # Send packet values to server
        serialized_values = pickle.dumps(values)
        client_socket.sendall(serialized_values)       
        table.insert('',0,iid=packet_number,text='', values=values)

    packet_number +=1
    start_time = datetime.now()

def on_treeview_doubleclick(event):
    selected_item = table.focus()
    packet_id = table.item(selected_item)["values"][0]
    global packet, packet_info
    packet = packet_list[packet_id-1]
    packet_info = str(packet.show(dump=True))
    tk.messagebox.showinfo(f"Packet Info (ID: {packet_id})", packet_info)
    
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def run_client():
    global host, port
    host = 'localhost'
    port = 12345

    global client_socket
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    create_username_ui()


def clear_window(window):
    window.destroy()

    create_gui()

def test_ip_address(ip_address):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Set a timeout value of 2 seconds

        # Attempt to connect to the IP address on port 80
        result = sock.connect_ex((ip_address, 80))

        # Check if the connection was successful
        if result == 0:
            return True
        else:
            return False

        sock.close()  # Close the socket

    except socket.error as e:
        print(f"An error occurred while testing the IP address: {str(e)}")

def create_username_ui():
    def connect(username_entry,ip_entry,port_entry):
            username = username_entry.get()
            server_ip = ip_entry.get()
            server_port = int(port_entry.get())
            if username.strip() == '' or server_ip.strip() == '':
                tk.messagebox.showerror("Error", "Not all fields were filled!") 
            elif not test_ip_address and not server_port.isdigit():
                tk.messagebox.showerror("Error", "Invalid input!") 
            else:
                # Connect to the server
                client_socket.connect((server_ip, server_port))
                print('[+] Connected to server:', server_ip, server_port)
                client_socket.send(('Username:' + username).encode())
                destroy = lambda: clear_window(window)
                destroy()

    window = ctk.CTk()
    window.title("Packet Sniffer")
    window.iconbitmap(r"Images\nose.ico")
    window.geometry("500x500")

    username_label = ctk.CTkLabel(window, text="Enter username:", font=("Assistant", 20, "bold"))
    username_label.place(relx=0.5, rely=0.2, anchor="center")

    username_entry = ctk.CTkEntry(window, font=("Assistant", 20))
    username_entry.place(relx=0.5, rely=0.26, anchor="center")

    ip_header = ctk.CTkLabel(window, text="Server IP:", font=("Assistant", 20, "bold"))
    ip_header.place(relx=0.5, rely=0.32, anchor="center")

    ip_entry = ctk.CTkEntry(window, font=("Assistant", 20))
    ip_entry.place(relx=0.5, rely=0.38, anchor="center")

    port_entry = ctk.CTkLabel(window, text="Server PORT:", font=("Assistant", 20, "bold"))
    port_entry.place(relx=0.5, rely=0.44, anchor="center")

    port_entry = ctk.CTkEntry(window, font=("Assistant", 20))
    port_entry.place(relx=0.5, rely=0.5, anchor="center")

    connect_button = ctk.CTkButton(window, text="Connect", command= lambda: connect(username_entry,ip_entry,port_entry), font=("Assistant", 20))
    connect_button.place(relx=0.5, rely=0.58, anchor="center")

    window.mainloop()


def on_closing():
    # Close the socket connection
    client_socket.close()
    print("[-] Disconnected.")

    # Destroy the GUI window
    root.destroy()

def get_input():
    global filter_input
    filter = filter_input.get()
    return filter


def create_gui():
    global root
    root = ctk.CTk()
    root.title("Packet Sniffer")
    root.iconbitmap(r"Images\nose.ico")
    root.geometry("700x500")
    root.protocol("WM_DELETE_WINDOW", on_closing)

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


    upper_frame = ctk.CTkFrame(root, corner_radius=10)
    upper_frame.pack(pady=20)

    global filter_input
    filter_input = ctk.CTkEntry(upper_frame, width=500, height=40, border_width=1, placeholder_text="Enter filter to apply...", text_color="silver", font=("Assistant", 20))
    filter_input.grid(row=0, column=0,padx=10,pady=10)

    start_button = ctk.CTkButton(upper_frame, image=start_img, text="", command=start_sniffing, width=20, height=35, fg_color="#212121", hover_color="#1c1c1c")
    start_button.grid(row=0, column=1, padx=5)

    stop_button = ctk.CTkButton(upper_frame, image=stop_img, text="", command=stop_sniffing, width=20, height=35, fg_color="#212121", hover_color="#1c1c1c")
    stop_button.grid(row=0, column=2, padx=5)

    output_frame = ctk.CTkFrame(root, width=500, corner_radius=10)
    output_frame.pack(pady=10)

    global table
    table = ttk.Treeview(output_frame)

    table = ttk.Treeview(output_frame)
    table['columns'] = ('packet_id', 'packet_time', 'packet_src', 'packet_dst', 'packet_protocol', 'packet_length','packet_info')

    table.column("#0", width=0, minwidth=0)
    table.column("packet_id",anchor=CENTER, width=80)
    table.column("packet_time",anchor=CENTER,width=80)
    table.column("packet_src",anchor=CENTER,width=80)
    table.column("packet_dst",anchor=CENTER,width=80)
    table.column("packet_protocol",anchor=CENTER,width=80)
    table.column("packet_length",anchor=CENTER,width=80)
    table.column("packet_info",anchor=CENTER,width=80)

    table.heading("#0",text="",anchor=CENTER)
    table.heading("packet_id",text="ID",anchor=CENTER)
    table.heading("packet_time",text="Time",anchor=CENTER)
    table.heading("packet_src",text="Source",anchor=CENTER)
    table.heading("packet_dst",text="Destination",anchor=CENTER)
    table.heading("packet_protocol",text="Protocol",anchor=CENTER)
    table.heading("packet_length",text="Length",anchor=CENTER)
    table.heading("packet_info",text="Info",anchor=CENTER)

    table.pack()
    table.bind("<Double-Button-1>", on_treeview_doubleclick)

    global main_sniffer
    main_sniffer = Sniffer(output_box=output_frame)

    root.mainloop()

# Create a thread object for the function
thread = threading.Thread(target=run_client)

# Start the thread
thread.start()