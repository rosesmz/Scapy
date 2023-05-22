import tkinter as tk
import customtkinter as ctk

def connect():
    username = input_entry.get()
    print("Connecting with username:", username)
    # Perform the connection logic here

window = ctk.CTk()
window.title("Packet Sniffer")
window.geometry("500x500")
window.configure(bg="black")

header_label = ctk.CTkLabel(window, text="Enter username:", font=("Arial", 20, "bold"))
header_label.place(relx=0.5, rely=0.38, anchor="center")

input_entry = ctk.CTkEntry(window)
input_entry.place(relx=0.5, rely=0.45, anchor="center")

connect_button = ctk.CTkButton(window, text="Connect", command=connect)
connect_button.place(relx=0.5, rely=0.52, anchor="center")

window.mainloop()
