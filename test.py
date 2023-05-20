from tkinter import *
from  tkinter import ttk


ws  = Tk()
ws.title('PythonGuides')
ws.geometry('500x500')
ws['bg'] = '#AC99F2'

output_frame = Frame(ws)
output_frame.pack()

#scrollbar
scroll = Scrollbar(output_frame)
scroll.pack(side=RIGHT, fill=Y)

scroll = Scrollbar(output_frame,orient='horizontal')
scroll.pack(side= BOTTOM,fill=X)

table = ttk.Treeview(output_frame,yscrollcommand=scroll.set, xscrollcommand =scroll.set)

scroll.config(command=table.yview)
scroll.config(command=table.xview)

table = ttk.Treeview(output_frame)

table['columns'] = ('player_id', 'player_name', 'player_Rank', 'player_states', 'player_city')

table.column("#0", width=0,  stretch=NO)
table.column("player_id",anchor=CENTER, width=80)
table.column("player_name",anchor=CENTER,width=80)
table.column("player_Rank",anchor=CENTER,width=80)
table.column("player_states",anchor=CENTER,width=80)
table.column("player_city",anchor=CENTER,width=80)

table.heading("#0",text="",anchor=CENTER)
table.heading("player_id",text="Id",anchor=CENTER)
table.heading("player_name",text="Name",anchor=CENTER)
table.heading("player_Rank",text="Rank",anchor=CENTER)
table.heading("player_states",text="States",anchor=CENTER)
table.heading("player_city",text="States",anchor=CENTER)


table.insert(parent='',index='end',iid=4,text='',
values=('5','CrissCross','105','California', 'San Diego'))
table.insert(parent='',index='end',iid=5,text='',
values=('6','ZaqueriBlack','106','Wisconsin' , 'TONY'))

table.pack()

ws.mainloop()