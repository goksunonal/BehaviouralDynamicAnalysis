import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox

def select_source_dir():
    source_dir = filedialog.askdirectory()
    source_dir_entry.delete(0, tk.END)
    source_dir_entry.insert(0, source_dir)

def select_destination_dir():
    destination_dir = filedialog.askdirectory()
    destination_dir_entry.delete(0, tk.END)
    destination_dir_entry.insert(0, destination_dir)

def move_files():
    source_directory = source_dir_entry.get()
    destination_directory = destination_dir_entry.get()

    if not source_directory or not destination_directory:
        messagebox.showerror("Error", "Please select both source and destination directories.")
        return


    os.makedirs(destination_directory, exist_ok=True)

    for root, dirs, files in os.walk(source_directory):
        for file in files:
            if file.endswith('.exe'):
                exe_path = os.path.join(root, file)
                xml_dir = exe_path + '_xml_dir'
                if os.path.isdir(xml_dir):
                    destination_path = os.path.join(destination_directory, file)
                    shutil.move(exe_path, destination_path)
                    log_text.insert(tk.END, f'Moved: {exe_path} to {destination_path}\n')

    messagebox.showinfo("Completed", "Files moved successfully.")


root = tk.Tk()
root.title("EXE File Mover")


tk.Label(root, text="Source Directory:").grid(row=0, column=0, padx=10, pady=5)
source_dir_entry = tk.Entry(root, width=50)
source_dir_entry.grid(row=0, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=select_source_dir).grid(row=0, column=2, padx=10, pady=5)

tk.Label(root, text="Destination Directory:").grid(row=1, column=0, padx=10, pady=5)
destination_dir_entry = tk.Entry(root, width=50)
destination_dir_entry.grid(row=1, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=select_destination_dir).grid(row=1, column=2, padx=10, pady=5)

tk.Button(root, text="Move Files", command=move_files).grid(row=2, column=0, columnspan=3, pady=20)

log_text = tk.Text(root, height=10, width=80)
log_text.grid(row=3, column=0, columnspan=3, padx=10, pady=10)


root.mainloop()
