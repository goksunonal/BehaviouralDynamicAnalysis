import os
from tkinter import Tk, Button, Label, filedialog, Listbox, Scrollbar, VERTICAL, RIGHT, Y, END

def get_unique_extensions(directory):
    extensions = set()
    for item in os.listdir(directory):
        if os.path.isfile(os.path.join(directory, item)):
            _, ext = os.path.splitext(item)
            if ext:
                extensions.add(ext.lower())
    return extensions

def browse_directory():
    directory = filedialog.askdirectory()
    if directory:
        extensions = get_unique_extensions(directory)
        display_extensions(extensions)

def display_extensions(extensions):
    listbox.delete(0, END)
    for ext in sorted(extensions):
        listbox.insert(END, ext)

# Set up the GUI
root = Tk()
root.title("Unique File Extensions Finder")

label = Label(root, text="Select a directory to list all unique file extensions:")
label.pack(pady=10)

browse_button = Button(root, text="Browse", command=browse_directory)
browse_button.pack(pady=5)

scrollbar = Scrollbar(root, orient=VERTICAL)
listbox = Listbox(root, yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

scrollbar.pack(side=RIGHT, fill=Y)
listbox.pack(padx=10, pady=10, expand=True, fill="both")

root.mainloop()
