import tkinter as tk

window = tk.Tk()
window.title("Tkinter Window")

# Create an upper frame
upper_frame = tk.Frame(window, bg="white")
upper_frame.pack(pady=20)

global username
username = 'yoyo'
# Define header labels with bold font
header_labels = [f"Username: {username}", "IP:", "PORT:"]
bold_font = ("Arial", 12, "bold")

# Create and place header labels in the upper frame
for idx, label_text in enumerate(header_labels):
    header_label = tk.Label(upper_frame, text=label_text, font=bold_font, bg="white")
    header_label.grid(row=0, column=idx, padx=10, pady=10)

window.mainloop()
