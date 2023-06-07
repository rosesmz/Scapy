import threading
import tkinter as tk
from tkinter import *
import tkinter.ttk as ttk
import customtkinter as ctk
import socket
import pickle

tableIsCreated = False

def create_table(username, client_address):
    global table

    upper_frame = ctk.CTkFrame(window)
    upper_frame.pack(pady=20)

    header_labels = [f"USERNAME: {username}", f"IP: {client_address[0]}", f"PORT: {client_address[1]}"]

    for idx, label_text in enumerate(header_labels):
        header_label = ctk.CTkLabel(upper_frame, text=label_text, font=("Assistant", 20))
        header_label.grid(row=0, column=idx, padx=10, pady=10)

    table_frame = ctk.CTkFrame(window, corner_radius=10)
    table_frame.place(relx=0.5, rely=0.5, anchor="center")

    table = ttk.Treeview(table_frame)

    table['columns'] = ('packet_id', 'packet_time', 'packet_src', 'packet_dst', 'packet_protocol','packet_length', 'packet_info')

    table.column("#0", width=0, minwidth=0)
    table.column("packet_id",anchor=CENTER,width=80, minwidth=60)
    table.column("packet_time",anchor=CENTER,width=80, minwidth=60)
    table.column("packet_src",anchor=CENTER,width=80, minwidth=60)
    table.column("packet_dst",anchor=CENTER,width=80, minwidth=60)
    table.column("packet_protocol",anchor=CENTER,width=80, minwidth=60)
    table.column("packet_length",anchor=CENTER,width=80, minwidth=60)
    table.column("packet_info",anchor=CENTER,width=80, minwidth=60)

    table.heading("#0",text="",anchor=CENTER)
    table.heading("packet_id",text="ID",anchor=CENTER)
    table.heading("packet_time",text="Time",anchor=CENTER)
    table.heading("packet_src",text="Source",anchor=CENTER)
    table.heading("packet_dst",text="Destination",anchor=CENTER)
    table.heading("packet_protocol",text="Protocol",anchor=CENTER)
    table.heading("packet_length",text="Length",anchor=CENTER)
    table.heading("packet_info",text="Info",anchor=CENTER)

    table.pack()

def run_server():
    global header
    global username
    username = ''
    host = socket.gethostname()
    port = 8000

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_socket.bind(('', port))

    # Listen for incoming connections
    server_socket.listen(1)
    print('[!] Server listening on {}:{}'.format(host, port))
    header = "Waiting for client..."

    # Accept a client connection
    global client_address
    client_socket, client_address = server_socket.accept()
    print('[+] Connected to client:', client_address)
    clear_window()
    
    while True:
        try:
            data = client_socket.recv(1024)

            if not data:
                break

            if data.startswith(b'Username:'):
                username = data.split(b':')[1].strip().decode()
            
            global tableIsCreated
            if not tableIsCreated:
                create_table(username, client_address)
                tableIsCreated = True
                continue

            client_packets = pickle.loads(data)
            if client_packets[0]:
                # table.insert(parent='',index='end',iid=client_packets[0],text='', values=client_packets)
                table.insert('',0,iid=client_packets[0],text='', values=client_packets)
        except KeyboardInterrupt:
            # Handle keyboard interrupt (e.g., Ctrl+C)
            pass

    print(f"[-] Client {client_address} disconnected.")

    # Close the connection
    client_socket.close()
    server_socket.close()

win_w = "700"
win_h = "500"

def animate_header():
    global header
    header_label.configure(text=header, font=("Assistant", 30, "bold"))
    header_label.after(400, animate_header)

    dots = header[-3:]
    if dots == "...":
        header = header[:-3]
    else:
        header += "."

def clear_window():
    header_label.destroy()


window = ctk.CTk()
window.title("Server Sniffer")
window.iconbitmap(r"Images\nose.ico")
window.geometry(win_w+"x"+win_h)
window.configure(bg="gray")

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

header = "Starting Server..."

header_label = ctk.CTkLabel(window, text=header, font=("Arial", 20, "bold"))
header_label.place(relx=0.5, rely=0.5, anchor="center")

animate_header()

# Create a thread object for the function
thread = threading.Thread(target=run_server)

# Start the thread
thread.start()

window.mainloop()