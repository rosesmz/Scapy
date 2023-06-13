# Import required libraries
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

# Global variables
was_stopped = False  # Flag indicating if the packet sniffing was stopped
packet_list = []  # List to store captured packets

# Sniffer class
class Sniffer:
    def __init__(self, output_box):
        self.is_running = False  # Flag indicating if the sniffer is running
        self.output_box = output_box  # Output box reference for GUI
        self.sniffer = None  # Sniffer object
    
    def setup_sniffer(self, count, entries_input):
        protocols = ['tcp', 'udp', 'http', 'icmp', 'arp', 'dns']  # Supported protocols for filtering
        filter = get_filter(entries_input).lower()  # Get the filter value from GUI input
        count_num = int(count)  # Convert count to integer
        # Set up the sniffer based on the specified filter
        if filter == 'http':
            self.sniffer = AsyncSniffer(filter='tcp port 80', prn=add_packet, store=False, count=count_num)
        elif filter == 'dns':
            self.sniffer = AsyncSniffer(filter='tcp port 53 or udp port 53', prn=add_packet, store=False, count=count_num)
        elif filter == '':
            self.sniffer = AsyncSniffer(filter='', prn=add_packet, store=False, count=count_num)
        elif filter not in protocols:
            # Show error message if the specified filter doesn't exist and run all protocols
            tk.messagebox.showerror("Error", "Specified filter doesn't exist!\nRunning all protocols.")
            self.sniffer = AsyncSniffer(filter='', prn=add_packet, store=False, count=count_num)
        else:
            self.sniffer = AsyncSniffer(filter=filter, prn=add_packet, store=False, count=count_num)
            
    def start_function(self):
        global start_time
        self.is_running = True
        self.sniffer.start()  # Start the packet sniffing process
        start_time = datetime.now()  # Record the start time
    
    def stop_function(self):
        global was_stopped
        if execution_time > 0.5:
            if self.is_running:
                was_stopped = True
                self.sniffer.stop()  # Stop the packet sniffing process
                self.is_running = False

# Start the packet sniffing process
def start_sniffing(entries_input):
    count_num = get_count(entries_input)
    if count_num == "" or count_num == "0":
        tk.messagebox.showerror("Error", "Please enter the number of packets to sniff!")
    else:  
        main_sniffer.setup_sniffer(count_num, entries_input)
        main_sniffer.start_function()

# Stop the packet sniffing process
def stop_sniffing():
    main_sniffer.stop_function()

# Get the protocol of a packet
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

# Global variables for packet tracking
packet_number = 1  # Packet number counter
is_first = True  # Flag indicating the first packet
execution_time = 0.0  # Total execution time
time_diff_converted = 0.0  # Time difference between packets
start_time = datetime.now()  # Start time

# Add a packet to the packet list and update the GUI
def add_packet(packet):
    global packet_number, start_time, execution_time, was_stopped
    end_time = datetime.now()  # Get the current time
    packet_list.append(packet)  # Add the packet to the list

    if was_stopped:
        time_diff_converted = 0.0
        was_stopped = False       
    else:
        # Calculating the difference between the last timer stop
        time_diff = (end_time - start_time)
        time_diff_converted = time_diff.total_seconds()
    execution_time += time_diff_converted  # Update the execution time

    values = ()
    try:
        # Determine the packet type and extract relevant information
        if HTTPRequest in packet or HTTPResponse in packet:
            values = (packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, 'HTTP', len(packet), packet.summary())
        elif IP and DNS in packet:
            values = (packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, 'DNS', len(packet), packet.summary())
        elif ARP in packet:
            values = (packet_number, round(execution_time, 6), packet[ARP].hwsrc, packet[ARP].hwdst, 'ARP', len(packet), packet.summary())     
        elif IP in packet:    
            values = (packet_number, round(execution_time, 6), packet[IP].src, packet[IP].dst, get_protocol(packet), len(packet), packet.summary())
    except:
        print("An exception occurred")

    if values:
        # Send packet values to server
        serialized_values = pickle.dumps(values)
        client_socket.sendall(serialized_values)       
        table.insert('', 0, iid=packet_number, text='', values=values)  # Update the GUI table with packet values

    packet_number += 1
    start_time = datetime.now()  # Reset the start time for the next packet

# Double-click event handler for the packet table
def on_treeview_doubleclick(event):
    selected_item = table.focus()
    packet_id = table.item(selected_item)["values"][0]
    global packet
    packet = packet_list[packet_id-1]
    packet_info = str(packet.show(dump=True))
    tk.messagebox.showinfo(f"Packet Info (ID: {packet_id})", packet_info)

# Set the appearance mode and color theme for the GUI
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Run the client thread
def run_client():
    global client_socket
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    create_username_ui()

# Test the validity of an IP address
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

# Clear labels from the GUI window
def clear_labels(labels, window):
    for label in labels:
        label.destroy()
    create_gui(window)


def connect(username_entry, ip_entry, port_entry, window, labels):
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
        clear_labels(labels, window)

# Create the username UI
def create_username_ui():
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

    port_header = ctk.CTkLabel(window, text="Server PORT:", font=("Assistant", 20, "bold"))
    port_header.place(relx=0.5, rely=0.44, anchor="center")

    port_entry = ctk.CTkEntry(window, font=("Assistant", 20))
    port_entry.place(relx=0.5, rely=0.5, anchor="center")

    connect_button = ctk.CTkButton(window, text="Connect", command=lambda: connect(username_entry, ip_entry, port_entry, window, labels), font=("Assistant", 20))
    connect_button.place(relx=0.5, rely=0.58, anchor="center")

    labels = [username_label, username_entry, ip_header, ip_entry, port_header, port_entry, connect_button]

    window.mainloop()

# Close the GUI window and disconnect from the server
def on_closing(root):
    # Close the socket connection
    client_socket.close()
    print("[-] Disconnected.")

    # Destroy the GUI window
    root.destroy()

# Get the filter value from input entries
def get_filter(entries_input):
    filter = entries_input[0].get()
    return filter

# Get the count value from input entries
def get_count(entries_input):
    count = entries_input[1].get()
    return count

# Validate numeric input for count entry
def validate_numeric_input(value):
    if value.isdigit() and int(value) <= 300:
        return True
    elif value == "":
        return True
    else:
        return False

# Create the GUI window
def create_gui(window):
    root = window
    root.title("Packet Sniffer")
    root.iconbitmap(r"Images\nose.ico")
    root.geometry("700x500")
    validation = root.register(validate_numeric_input)
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root))

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

    start_img = ctk.CTkImage(light_image=Image.open(r"Images\play.png"), size=(20, 20))
    stop_img = ctk.CTkImage(light_image=Image.open(r"Images\stop.png"), size=(20, 20))

    upper_frame = ctk.CTkFrame(root, corner_radius=10)
    upper_frame.pack(pady=20)

    filter_input = ctk.CTkEntry(upper_frame, width=500, height=40, border_width=1, placeholder_text="Enter filter to apply...", text_color="silver", font=("Assistant", 20))
    filter_input.grid(row=0, column=0, padx=10, pady=10)

    packet_number = ctk.CTkLabel(upper_frame, text="Number of packets:", font=("Assistant", 20))
    packet_number.grid(row=1, column=0, padx=10, pady=10, sticky="w")

    count_input = ctk.CTkEntry(upper_frame, placeholder_text="Number of packets...", validate="key", validatecommand=(validation, "%P"), width=150, height=40, border_width=1, text_color="silver", font=("Assistant", 20))
    count_input.grid(row=1, column=0, padx=1, pady=10)

    entries_input = [filter_input, count_input]

    start_button = ctk.CTkButton(upper_frame, image=start_img, text="", command=lambda: start_sniffing(entries_input), width=20, height=35, fg_color="#212121", hover_color="#1c1c1c")
    start_button.grid(row=0, column=1, padx=5)

    stop_button = ctk.CTkButton(upper_frame, image=stop_img, text="", command=stop_sniffing, width=20, height=35, fg_color="#212121", hover_color="#1c1c1c")
    stop_button.grid(row=0, column=2, padx=5)

    output_frame = ctk.CTkFrame(root, width=500, corner_radius=10)
    output_frame.pack(pady=10)

    global table
    table = ttk.Treeview(output_frame)

    table = ttk.Treeview(output_frame)
    table['columns'] = ('packet_id', 'packet_time', 'packet_src', 'packet_dst', 'packet_protocol', 'packet_length', 'packet_info')

    table.column("#0", width=0, minwidth=0)
    table.column("packet_id", anchor=CENTER, width=80)
    table.column("packet_time", anchor=CENTER, width=80)
    table.column("packet_src", anchor=CENTER, width=80)
    table.column("packet_dst", anchor=CENTER, width=80)
    table.column("packet_protocol", anchor=CENTER, width=80)
    table.column("packet_length", anchor=CENTER, width=80)
    table.column("packet_info", anchor=CENTER, width=80)

    table.heading("#0", text="", anchor=CENTER)
    table.heading("packet_id", text="ID", anchor=CENTER)
    table.heading("packet_time", text="Time", anchor=CENTER)
    table.heading("packet_src", text="Source", anchor=CENTER)
    table.heading("packet_dst", text="Destination", anchor=CENTER)
    table.heading("packet_protocol", text="Protocol", anchor=CENTER)
    table.heading("packet_length", text="Length", anchor=CENTER)
    table.heading("packet_info", text="Info", anchor=CENTER)

    table.pack()
    table.bind("<Double-Button-1>", on_treeview_doubleclick)

    global main_sniffer
    main_sniffer = Sniffer(output_box=output_frame)

    root.mainloop()

# Create a thread object for the function
thread = threading.Thread(target=run_client)

# Start the thread
thread.start()