import threading
import tkinter as tk
from tkinter import *
import tkinter.ttk as ttk
import customtkinter as ctk
import time
import socket
import pickle

def run_server():
    global header
    host = 'localhost'
    port = 12345

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen(1)
    print('Server listening on {}:{}'.format(host, port))
    header = "Waiting for client..."

    # Accept a client connection
    client_socket, client_address = server_socket.accept()
    print('Connected to client:', client_address)
    clear_window()
    
    while True:
        # Receive data from the client
        data = client_socket.recv(1024)
        if not data:
            break

        # Display the received message
        received_tuple = pickle.loads(data)
        if received_tuple[0]:
            # table.insert(parent='',index='end',iid=received_tuple[0],text='', values=received_tuple)
            table.insert('',0,iid=received_tuple[0],text='', values=received_tuple)

    # Close the connection
    client_socket.close()
    server_socket.close()

win_w = "700"
win_h = "500"

def animate_header():
    global header
    header_label.config(text=header)
    header_label.after(300, animate_header)

    dots = header[-3:]
    if dots == "...":
        header = header[:-3]
    else:
        header += "."

def clear_window():
    header_label.destroy()
    # button.destroy()

    create_table()

def create_table():
    global input_label, input_entry, add_button, table

    column_width = 80
    # total_width = len(treeview["columns"]) * column_width
    total_width = 7 * column_width

    table_frame = ctk.CTkFrame(window, corner_radius=10)
    table_frame.place(relx=0.5, rely=0.5, anchor="center")

    table = ttk.Treeview(table_frame)

    table['columns'] = ('packet_id', 'pack_time', 'pack_src', 'pack_dst', 'pack_protocol','pack_len', 'pack_content')

    table.column("#0", width=0, minwidth=0)
    # table.column("client_id",anchor=CENTER, width=80, minwidth=60)
    # table.column("client_name",anchor=CENTER,width=80, minwidth=60)
    table.column("packet_id",anchor=CENTER,width=80, minwidth=60)
    table.column("pack_time",anchor=CENTER,width=80, minwidth=60)
    table.column("pack_src",anchor=CENTER,width=80, minwidth=60)
    table.column("pack_dst",anchor=CENTER,width=80, minwidth=60)
    table.column("pack_protocol",anchor=CENTER,width=80, minwidth=60)
    table.column("pack_len",anchor=CENTER,width=80, minwidth=60)
    table.column("pack_content",anchor=CENTER,width=80, minwidth=60)

    table.heading("#0",text="",anchor=CENTER)
    # table.heading("client_id",text="Client ID",anchor=CENTER)
    # table.heading("client_name",text="Client Name",anchor=CENTER)
    table.heading("packet_id",text="Pack ID",anchor=CENTER)
    table.heading("pack_time",text="Pack Time",anchor=CENTER)
    table.heading("pack_src",text="Pack SRC",anchor=CENTER)
    table.heading("pack_dst",text="Pack DST",anchor=CENTER)
    table.heading("pack_protocol",text="Pack Protocol",anchor=CENTER)
    table.heading("pack_len",text="Pack Len",anchor=CENTER)
    table.heading("pack_content",text="Pack Content",anchor=CENTER)

    table.pack()

def add_to_table():
    text = input_entry.get()
    treeview.insert(tk.END, text)
    input_entry.delete(0, tk.END)

window = tk.Tk()
window.title("Server Sniffer")
window.geometry(win_w+"x"+win_h)
window.configure(background="black")

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

header_label = tk.Label(window, text=header, fg="white", bg="black", font=("Arial", 16, "bold"))
header_label.place(relx=0.5, rely=0.5, anchor="center")

animate_header()

# Create a thread object for the function
thread = threading.Thread(target=run_server)

# Start the thread
thread.start()

# button = tk.Button(window, text="Create Table", command=clear_window)
# button.place(relx=0.5, rely=0.6, anchor="center")

window.mainloop()
