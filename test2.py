import tkinter as tk
from tkinter import ttk

# Create the main window
root = tk.Tk()
root.title('Table in Frame')

# Create a frame to hold the table
frame = ttk.Frame(root)
frame.pack(fill='both', expand=True)

# Create a table as a child of the frame
table = ttk.Treeview(frame)
table.grid(row=0, column=0, sticky='nsew')

# Add some sample data to the table
for i in range(1, 21):
    table.insert(parent='', index='end', iid=i, text='', values=('Person {}'.format(i), i * 5, 'Country {}'.format(i)))

# Configure the columns
table['columns'] = ('Name', 'Age', 'Country')
table.column('#0', width=0, stretch='no')
table.column('Name', anchor='w', width=100)
table.column('Age', anchor='center', width=50)
table.column('Country', anchor='center', width=100)
table.heading('#0', text='', anchor='w')
table.heading('Name', text='Name', anchor='w')
table.heading('Age', text='Age', anchor='center')
table.heading('Country', text='Country', anchor='center')

# Create a vertical scrollbar
y_scrollbar = ttk.Scrollbar(frame, orient='vertical', command=table.yview)
y_scrollbar.grid(row=0, column=1, sticky='ns')

# Configure the table to use the vertical scrollbar
table.configure(yscrollcommand=y_scrollbar.set)

# Create a horizontal scrollbar
x_scrollbar = ttk.Scrollbar(root, orient='horizontal', command=table.xview)
x_scrollbar.pack(side='bottom', fill='x')

# Configure the table to use the horizontal scrollbar
table.configure(xscrollcommand=x_scrollbar.set)

# Configure the grid weights to fill the frame
frame.columnconfigure(0, weight=1)
frame.rowconfigure(0, weight=1)

# Start the main event loop
root.mainloop()
