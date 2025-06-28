import datetime
import os
import shutil
import threading
import time
import tkinter as tk
from tkinter import filedialog

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
processed_files = set()
log_entries = []
FILES_DIR = ""
LOGS_DIR = ""
file_types = [".exe"]

currentSkippedCount = 0


def checkIfFileHasLogs():
    global currentSkippedCount
    source_directory = FILES_DIR
    logs_directory = LOGS_DIR
    processed_files.clear()
    for root, dirs, files in os.walk(source_directory):
        for file in files:
            if any(file.endswith(ext) for ext in file_types):
                zip_path = logs_directory + '/' + file + '.zip'
                if os.path.exists(zip_path):
                    log(f'file skipped: {file}')
                else:
                    log(f'file not skipped: {file}')
                    if currentSkippedCount > 3:
                        moved_path = logs_directory + '/special'
                        os.makedirs(moved_path, exist_ok=True)
                        move_files(source_directory + '/' + file, moved_path)
                        currentSkippedCount = 0
                        continue
                    else:
                        currentSkippedCount += 1
                        return file
    return None


def move_files(exe_path, destination_path):
    shutil.move(exe_path, destination_path)
    log("Files moved successfully.")


@app.route('/get_next_file', methods=['GET'])
def get_next_file():
    print("get_next_file files dir:" + FILES_DIR)
    print("get_next_file files log_dır:" + LOGS_DIR)
    next_file = checkIfFileHasLogs()
    if next_file is not None:
        log(f"Sending file: {next_file}")
        return jsonify({'file': next_file})
    log("No more files to process.")
    return jsonify({'file': None})


@app.route('/upload_log', methods=['POST'])
def upload_log():
    global LOGS_DIR, currentSkippedCount

    if 'log' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part in the request'}), 400

    log_files = request.files.getlist('log')

    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)

    for log_file in log_files:
        if log_file.filename == '':
            continue

        log_filename = os.path.join(LOGS_DIR, log_file.filename)
        log_file.save(log_filename)
        log(f"Log uploaded: {log_file.filename}")
        currentSkippedCount = 0

    return jsonify({'status': 'success'})


@app.route('/set_directories', methods=['POST'])
def set_directories():
    global FILES_DIR, LOGS_DIR
    data = request.get_json()
    FILES_DIR = data['files_dir']
    LOGS_DIR = data['logs_dir']
    log(f"Directories set. Files: {FILES_DIR}, Logs: {LOGS_DIR}")
    return jsonify({'status': 'success'})


@app.route('/get_logs', methods=['GET'])
def get_logs():
    return jsonify({'logs': log_entries})


def log(message):
    global log_entries
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"{timestamp} - {message}"
        log_entries.append(log_message)
        print(log_message)

        with open("server_exe_logfile.txt", "a") as log_file:
            log_file.write(log_message + "\n")
    except Exception as e:
        print(e)


def start_flask_app():
    files_dir = files_dir_var.get()
    logs_dir = logs_dir_var.get()
    if files_dir and logs_dir:
        global FILES_DIR, LOGS_DIR
        FILES_DIR = files_dir
        LOGS_DIR = logs_dir
        flask_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5000))
        flask_thread.daemon = True
        flask_thread.start()
        start_log_fetch_thread()


def start_log_fetch_thread():
    log_fetch_thread = threading.Thread(target=fetch_logs)
    log_fetch_thread.daemon = True
    log_fetch_thread.start()


def fetch_logs():
    while True:
        try:
            response = requests.get('http://127.0.0.1:5000/get_logs')
            if response.status_code == 200:
                logs = response.json()['logs']
                logcat_text.delete(1.0, tk.END)
                logcat_text.insert(tk.END, "\n".join(logs))
                logcat_text.yview(tk.END)
            time.sleep(2)
        except requests.RequestException as e:
            logcat_text.insert(tk.END, f"Error fetching logs: {e}")
            logcat_text.yview(tk.END)
            break


root = tk.Tk()
root.title("TCP Non-Exe Server")

files_dir_var = tk.StringVar()
logs_dir_var = tk.StringVar()

tk.Label(root, text="Select Directory with Files:").pack()
tk.Entry(root, textvariable=files_dir_var, width=50).pack()
tk.Button(root, text="Browse", command=lambda: files_dir_var.set(filedialog.askdirectory())).pack()

tk.Label(root, text="Select Directory for Exported Logs:").pack()
tk.Entry(root, textvariable=logs_dir_var, width=50).pack()
tk.Button(root, text="Browse", command=lambda: logs_dir_var.set(filedialog.askdirectory())).pack()

tk.Button(root, text="Start Server", command=start_flask_app).pack()

logcat_label = tk.Label(root, text="Logcat Output:")
logcat_label.pack()
logcat_text = tk.Text(root, height=10, width=80)
logcat_text.pack()

root.mainloop()
