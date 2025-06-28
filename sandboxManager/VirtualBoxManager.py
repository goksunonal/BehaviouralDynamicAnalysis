import ctypes
import datetime
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog

VM_NAME = "Dynamic Analysis File Server"
SNAPSHOT_NAME = "Snapshot 10"
REVERT_INTERVAL = 120
STOP_INTERVAL = 5

COUNT = 0
CONTINUE_LOOP = False
VBOX_PATH = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"


def revert_snapshot(vm_name, snapshot_name, isHeadless):
    try:
        subprocess.run([VBOX_PATH, "snapshot", vm_name, "restore", snapshot_name], check=True)
        log(f"VM STATE:{get_vm_state()}")
        wait_for_vm_restoring_end()
        log(f"Reverted to snapshot {snapshot_name} and started VM {vm_name}.")
        log(f"VM STATE before start:{get_vm_state()}")
        if isHeadless:
            subprocess.run([VBOX_PATH, "startvm", vm_name, "--type", "headless"], check=True)
        else:
            subprocess.run([VBOX_PATH, "startvm", vm_name], check=True)
        log(f"VM STATE:{get_vm_state()}")
        wait_for_vm_running()
        log(f"Started the VM")
    except subprocess.CalledProcessError as e:
        log(f"Error reverting snapshot: {e}")


def log(message):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"{timestamp} - {message}"
    logcat_text.insert(tk.END, log_message + '\n')
    logcat_text.yview(tk.END)
    print(log_message)

    with open("server_exe_logfile.txt", "a") as log_file:
        log_file.write(log_message + "\n")

def get_vm_state():
    try:
        result = subprocess.run(
            [VBOX_PATH, "showvminfo", VM_NAME, "--machinereadable"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if line.startswith("VMState="):
                return line.split("=")[1].strip().strip('"')
    except subprocess.CalledProcessError as e:
        log(f"Error getting VM state: {e}")
    return None


def wait_for_vm_poweroff():
    while True:
        state = get_vm_state()
        if state == "poweroff":
            break
        log(f"Waiting for VM {VM_NAME} to power off. Current state: {state}")
        time.sleep(5)


def wait_for_vm_running():
    while True:
        state = get_vm_state()
        if state == "running":
            break
        log(f"Waiting for VM {VM_NAME} to run. Current state: {state}")
        time.sleep(5)


def wait_for_vm_restoring_end():
    while True:
        state = get_vm_state()
        if state == "saved" or state == "poweroff":
            break
        log(f"Waiting for VM {VM_NAME} to restoring. Current state: {state}")
        subprocess.run([VBOX_PATH, "startvm", VM_NAME, "--type", "emergencystop"], check=True)
        subprocess.run([VBOX_PATH, "controlvm", VM_NAME, "poweroff"], check=True)
        time.sleep(5)


def run_program():
    guest_exe_path = exe_path_var.get()
    client_name = username_var.get()
    client_pass = pass_var.get()
    sample_path = sample_path_var.get()
    url_path = ip_var.get()
    timeout = exe_timeout_var.get()
    subprocess.run(
        [VBOX_PATH, "guestcontrol", VM_NAME, "run", "--exe", guest_exe_path, "--username", client_name, "--password",
         client_pass, "--wait-stdout", "-- \\", sample_path, url_path, timeout], check=True)
    time.sleep(30)


def startLoop(headless):
    global COUNT, CONTINUE_LOOP, VBOX_PATH
    path = directory_var.get()
    if path is not None and path != "":
        VBOX_PATH = path
    COUNT = 0
    while CONTINUE_LOOP:
        try:
            COUNT = COUNT + 1
            log("Process Count: " + str(COUNT))
            revert_snapshot(VM_NAME, SNAPSHOT_NAME, headless)
            time.sleep(REVERT_INTERVAL)
            subprocess.run([VBOX_PATH, "controlvm", VM_NAME, "poweroff"], check=True)
            log(f"VM STATE:{get_vm_state()}")
            wait_for_vm_poweroff()
            time.sleep(STOP_INTERVAL)
            log(f"Stopped the VM")
        except Exception as e:
            log(f"Exception occurred: {e}")


def start():
    global CONTINUE_LOOP
    CONTINUE_LOOP = True
    thread = threading.Thread(target=startLoop, args=[False])
    thread.start()


def startHeadless():
    global CONTINUE_LOOP
    CONTINUE_LOOP = True
    thread = threading.Thread(target=startLoop, args=[True])
    thread.start()


def stop():
    global CONTINUE_LOOP
    CONTINUE_LOOP = False


def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)


def browse_directory():
    directory_path = filedialog.askdirectory()
    if directory_path:
        directory_var.set(directory_path)


run_as_admin()
root = tk.Tk()
root.title("Virtual Box Manager")

directory_label = tk.Label(root, text='Enter the VBOX PATH:')
directory_label.pack()
directory_var = tk.StringVar()
directory_entry = tk.Entry(root, textvariable=directory_var)
directory_entry.pack()
browse_button = tk.Button(root, text='Browse', command=browse_directory)
browse_button.pack()

exe_path_label = tk.Label(root, text='Enter the path of exe file in virtual machine:')
exe_path_label.pack()
exe_path_var = tk.StringVar()
exe_path_entry = tk.Entry(root, textvariable=exe_path_var)
exe_path_entry.pack()

sample_path_label = tk.Label(root, text='Enter the path of sample files in virtual machine:')
sample_path_label.pack()
sample_path_var = tk.StringVar()
sample_path_entry = tk.Entry(root, textvariable=sample_path_var)
sample_path_entry.pack()

ip_label = tk.Label(root, text='Enter the server ip:')
ip_label.pack()
ip_var = tk.StringVar()
ip_entry = tk.Entry(root, textvariable=ip_var)
ip_entry.pack()

exe_timeout_label = tk.Label(root, text='Enter the exe timeout:')
exe_timeout_label.pack()
exe_timeout_var = tk.StringVar()
exe_timeout_entry = tk.Entry(root, textvariable=exe_timeout_var)
exe_timeout_entry.pack()

username_label = tk.Label(root, text='Enter the username of guest:')
username_label.pack()
username_var = tk.StringVar()
username_entry = tk.Entry(root, textvariable=username_var)
username_entry.pack()

pass_label = tk.Label(root, text='Enter the password of guest:')
pass_label.pack()
pass_var = tk.StringVar()
pass_entry = tk.Entry(root, textvariable=pass_var)
pass_entry.pack()

tk.Button(root, text="Start Headless Server", command=startHeadless).pack()
tk.Button(root, text="Start Windowed Server", command=start).pack()

tk.Button(root, text="Stop Server", command=stop).pack()

logcat_label = tk.Label(root, text="Logcat Output:")
logcat_label.pack()
logcat_text = tk.Text(root, height=10, width=80)
logcat_text.pack()

root.mainloop()
