import csv
import ctypes
import io
import json
import logging
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
import xml.etree.ElementTree as ET
from datetime import datetime
from tkinter import filedialog

import dateutil.parser
import psutil
import win32com.client
import win32evtlog
import xmltodict
from scapy.all import sniff
from scapy.utils import PcapWriter


def generate_mock_argument(param, param_default):
    if param.annotation == int:
        return 1
    elif param.annotation == float:
        return 1.0
    elif param.annotation == str:
        return "mock"
    elif param.annotation == bool:
        return True
    elif param.annotation == bytes:
        return b"mock"
    else:
        if param_default is None:
            return 1
        elif 'inspect._empty' in f"{param_default}":
            return "1"
        else:
            return param_default


def generate_mock_argument2(param, param_default):
    if param.annotation == int:
        return 1
    elif param.annotation == float:
        return 1.0
    elif param.annotation == str:
        return "mock"
    elif param.annotation == bool:
        return True
    elif param.annotation == bytes:
        return b"mock"
    else:
        if param_default is None:
            return 1
        elif 'inspect._empty' in f"{param_default}":
            return ctypes.WinDLL.__format__
        else:
            return param_default


def invoke_dll(func):
    for num in range(1, 27):
        try:
            if num == 1:
                print(f"- {func()}")
            elif num == 2:
                print(f"1 - {func(1)}")
            elif num == 3:
                print(f"2 - {func(1, 1)}")
            elif num == 4:
                print(f"3 - {func(1, 1, 1)}")
            elif num == 5:
                print(f"4 - {func(1, 1, 1, 1)}")
            elif num == 6:
                print(f"5 - {func(1, 1, 1, 1, 1)}")
            elif num == 7:
                print(f"6 - {func(1, 1, 1, 1, 1, 1)}")
            elif num == 8:
                result = func("1")
                print(f"7 - {result}")
            elif num == 9:
                result = func("1", "1")
                print(f"8 - {result}")
            elif num == 10:
                result = func("1", "1", "1")
                print(f"9 - {result}")
            elif num == 11:
                result = func("1", "1", "1", "1")
                print(f"10 - {result}")
            elif num == 12:
                result = func("1", "1", "1", "1", "1")
                print(f"11 - {result}")
            elif num == 13:
                result = func("1", "1", "1", "1", "1", "1")
                print(f"12 - {result}")
            elif num == 14:
                result = func("1", 1)
                print(f"13 - {result}")
            elif num == 15:
                result = func(1, "1")
                print(f"14 - {result}")
            elif num == 16:
                result = func("1", 1, "1")
                print(f"15 - {result}")
            elif num == 17:
                result = func(1, "1", 1)
                print(f"16 - {result}")
            elif num == 18:
                result = func(True)
                print(f"17 - {result}")
            elif num == 19:
                result = func(True, False)
                print(f"18 - {result}")
            elif num == 20:
                result = func(True, True, True)
                print(f"19 - {result}")
            elif num == 21:
                result = func(True, True, True, True)
                print(f"20 - {result}")
            elif num == 22:
                result = func(None, None, None, None, None)
                print(f"21 - {result}")
            elif num == 23:
                result = func(True, "1")
                print(f"22 - {result}")
            elif num == 24:
                result = func(True, 1)
                print(f"23 - {result}")
            elif num == 25:
                result = func(1, True)
                print(f"24 - {result}")
            elif num == 26:
                result = func("1", True)
                print(f"25 - {result}")
        except Exception as e:
            print(f"invoke dll exception count:{num} {e}")
            continue


def execute_dlls_in_folder(dll_path):
    try:
        cmd = ['dumpbin', '/exports', dll_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        lines = result.stdout.splitlines()
        function_names = []

        readyForFunctions = False
        for line in lines:
            parts = line.split()
            if "ordinal" in parts and "RVA" in parts:
                readyForFunctions = True
                continue
            if "Summary" in parts:
                break
            if readyForFunctions and len(parts) >= 4 and parts[3].strip():
                function_name = parts[3].strip()
                function_names.append(function_name)

        for func_name in function_names:
            print(f"func:{func_name}")
            try:
                dll = ctypes.CDLL(dll_path)
                print(f"CALLABLE FUNCTION:- {func_name}")
                func = getattr(dll, func_name)

                try:
                    invoke_dll(func)
                except Exception as e:
                    print(f"Error calling function '{func_name}': {e}")
            except Exception as e:
                print(f"Error processing attribute '{func_name}': {e}")
    except Exception as e:
        print(f"Error processing file '{dll_path}': {e}")


def terminate_process_by_pid(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        for child in p.children(recursive=True):
            child.terminate()
        p.wait(2)
        if p.is_running():
            p.kill()
    except psutil.NoSuchProcess:
        print('Process found dead, no need to kill')


def capture_packets(network_log_file, timeout):
    try:
        writer = PcapWriter(network_log_file)
        packets = sniff(timeout=timeout)
        for packet in packets:
            writer.write(packet)
        writer.flush()
    except Exception as e:
        print(f'An capture packet error occurred: {str(e)}')


def is_exe_shortcut(shortcut_path):
    try:
        shell = win32com.client.Dispatch('WScript.Shell')
        return shell.CreateShortCut(shortcut_path).Targetpath.lower().endswith('.exe')
    except Exception:
        return False


def lnk_file_path(shortcut_path):
    try:
        shell = win32com.client.Dispatch('WScript.Shell')
        return shell.CreateShortCut(shortcut_path).Targetpath
    except Exception:
        return 'False'


def analyze_folder(loop_count, dir_path, timeout, logcat_text, fullAnalyze):
    file_types = [".dll", ".img", ".dmg", ".elf", ".hta", ".jar", ".js", ".lic", ".macho", ".pdf", ".xls",
                  ".xlsm", ".xlsx", ".doc", ".r09", ".reg", ".rtf", ".inf", ".sh", ".vbs", ".sys", ".txt", ".vbe",
                  ".bat", ".cmd", ".msi", ".ps1", ".wsf", ".docx"]
    files_to_analyze = [file for file in os.listdir(dir_path) if any(file.endswith(ext) for ext in file_types)]
    lnk_files = [lnk_file_path(dir_path + '/' + file) for file in os.listdir(dir_path) if
                 (file.endswith('.lnk') and is_exe_shortcut(dir_path + '/' + file))]
    files_to_analyze += lnk_files
    filesDir = os.listdir('C:\\Windows\\System32\\winevt\\Logs')
    evtx_files = [file for file in filesDir if file.endswith('.evtx')]

    for i in range(1, loop_count + 1):
        for filename in files_to_analyze:
            directory_name = dir_path + '/' + os.path.basename(filename) + '_xml_dir'
            if not os.path.exists(directory_name):
                os.mkdir(directory_name)
            network_path = directory_name + '\\' + 'xml_network_dir'
            if not os.path.exists(network_path):
                os.mkdir(network_path)
            time_running_logs = open(os.path.join(directory_name, 'time_log.txt'), 'a')
            logcat_logs = open(os.path.join(directory_name, 'logcat_log.txt'), 'a', encoding='utf8')
            logcat_logs.write(
                '-----------------------------------------------------------------------------------------\n')
            start_time = time.time()
            network_log_file = os.path.join(network_path, 'network_log_' + str(start_time) + '.pcap')
            end_time = start_time + timeout + 2
            time_running_logs.write(str(start_time) + ',' + str(end_time) + '\n')
            time_running_logs.close()
            packet_capture_thread = threading.Thread(target=capture_packets, args=(network_log_file, timeout))
            try:
                full_file = dir_path + '/' + filename
                if filename.endswith('.exe'):
                    process = subprocess.Popen(full_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                elif filename.endswith('.dll'):
                    execute_dlls_in_folder(full_file)
                    process = subprocess.Popen(full_file, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    process = subprocess.Popen(full_file, stdout=subprocess.PIPE, shell=True)
                packet_capture_thread.start()
                while time.time() < end_time:
                    continue
                terminate_process_by_pid(process.pid)
                if filename.endswith('.exe'):
                    for line in io.TextIOWrapper(process.stdout, encoding='utf-8'):
                        logcat_logs.write(line)
            except Exception as e:
                print(f'An error occurred: {str(e)}')
            end_time = time.time()
            time.sleep(2)
            start_time_date = datetime.fromtimestamp(start_time)
            end_time_date = datetime.fromtimestamp(end_time)
            print('Start time:', start_time_date)
            print('End time:', end_time_date)
            logcat_logs.close()
            server = 'localhost'
            event_count = 0
            for logtype in evtx_files:
                try:
                    writer = None
                    procCount = 0
                    print('Processing:' + logtype + '\n')
                    hand = win32evtlog.EvtQuery('C:\\Windows\\System32\\winevt\\Logs\\' + logtype,
                                                win32evtlog.EvtQueryFilePath | win32evtlog.EvtQueryReverseDirection)
                    count = 0
                    addedEvent = []
                    last_event = None
                    sessionFinished = True
                    while sessionFinished:
                        events = win32evtlog.EvtNext(hand, 100)
                        if len(events) == 0:
                            print('Zero log number for ' + str(logtype) + ' is count:' + str(count))
                            print('Event list finished')
                            if not len(addedEvent) == 0:
                                csv_file = open(os.path.join(directory_name, lowtype + '.csv'), 'a', encoding='UTF8',
                                                newline='')
                                writer = csv.writer(csv_file)
                                if csv_file.tell() == 0:
                                    writer.writerow(['Event'])
                                for data in addedEvent:
                                    writer.writerow([data])
                                csv_file.close()
                                event_count = event_count + procCount
                                if last_event:
                                    print('Time Generated last event:' + str(last_event))
                            sessionFinished = False
                        elif events:
                            for event in events:
                                count = count + 1
                                xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                                ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
                                xml_content = ET.fromstring(xml)
                                xml_dict = xmltodict.parse(xml)
                                system_time_created = xml_dict['Event']['System']['TimeCreated']
                                time_created = system_time_created['@SystemTime']
                                system_time = dateutil.parser.isoparse(time_created)
                                system_timestamp = system_time.timestamp()
                                json_string = json.dumps(xml_dict, indent=0)
                                replaced_string = json_string.replace('\r', '').replace('\n', '')
                                generated = datetime.fromtimestamp(system_timestamp)
                                if not fullAnalyze and system_timestamp < start_time:
                                    sessionFinished = False
                                    print('Time log number for ' + str(logtype) + ' is count:' + str(count))
                                    print('Event list finished')
                                    if not len(addedEvent) == 0:
                                        csv_file = open(os.path.join(directory_name, logtype + '.csv'), 'a',
                                                        encoding='UTF8', newline='')
                                        writer = csv.writer(csv_file)
                                        if csv_file.tell() == 0:
                                            writer.writerow(['Event'])
                                        for data in addedEvent:
                                            writer.writerow([data])
                                        csv_file.close()
                                        event_count = event_count + procCount
                                        if last_event:
                                            print('Time Generated last event:' + str(last_event))
                                    break
                                else:
                                    if last_event is None:
                                        last_event = generated
                                    if end_time >= system_timestamp >= start_time:
                                        procCount = procCount + 1
                                        print('Event Added ' + str(generated))
                                        addedEvent.append(replaced_string)
                        else:
                            print('Log number for ' + str(logtype) + ' is count:' + str(count))
                            print('Event list finished')
                            if not len(addedEvent) == 0:
                                csv_file = open(os.path.join(directory_name, logtype + '.csv'), 'a', encoding='UTF8',
                                                newline='')
                                writer = csv.writer(csv_file)
                                if csv_file.tell() == 0:
                                    writer.writerow(['Event'])
                                for data in addedEvent:
                                    writer.writerow([data])
                                csv_file.close()
                                event_count = event_count + procCount
                                if last_event:
                                    print('Time Generated last event:' + str(last_event))
                            sessionFinished = False
                            pass
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
            logcat_text.insert(tk.END, 'Count Of Event for ' + filename + ' is ' + str(event_count) + '\n')


def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)


def browse_directory():
    directory_path = filedialog.askdirectory()
    if directory_path:
        directory_var.set(directory_path)


def start_process():
    run_as_admin()
    selected_directory = directory_var.get()
    timeout = timeout_entry.get()
    loop_count = int(loop_entry.get())
    print('Selected Directory:', selected_directory)
    print('Timeout:', timeout)
    logcat_text.insert(tk.END, 'Selected Directory:' + selected_directory + '\n')
    logcat_text.insert(tk.END, 'Timeout:' + timeout + '\n')
    exe_thread = threading.Thread(target=analyze_folder,
                                  args=(loop_count, selected_directory, int(timeout), logcat_text, False))
    exe_thread.start()


def start_process_full():
    run_as_admin()
    selected_directory = directory_var.get()
    timeout = timeout_entry.get()
    print('Selected Directory:', selected_directory)
    print('Timeout:', timeout)
    loop_count = int(loop_entry.get())
    logcat_text.insert(tk.END, 'Selected Directory:' + selected_directory + '\n')
    logcat_text.insert(tk.END, 'Timeout:' + timeout + '\n')
    exe_thread = threading.Thread(target=analyze_folder,
                                  args=(loop_count, selected_directory, int(timeout), logcat_text, True))
    exe_thread.start()


def clear_logcat():
    logcat_text.delete(1.0, tk.END)


run_as_admin()
root = tk.Tk()
root.title('Dynamic Exe Analyzer')
directory_label = tk.Label(root, text='Select a directory:')
directory_label.pack()
directory_var = tk.StringVar()
directory_entry = tk.Entry(root, textvariable=directory_var)
directory_entry.pack()
browse_button = tk.Button(root, text='Browse', command=browse_directory)
browse_button.pack()
timeout_label = tk.Label(root, text='Set Timeout (seconds):')
timeout_label.pack()
timeout_entry = tk.Entry(root)
timeout_entry.pack()
loop_counter = tk.Label(root, text='How many times do you want to run?')
loop_counter.pack()
loop_entry = tk.Entry(root)
loop_entry.pack()
start_button = tk.Button(root, text='Analyze', command=start_process)
start_button.pack()
start_button_full = tk.Button(root, text='Full Analyze', command=start_process_full)
start_button_full.pack()
logcat_label = tk.Label(root, text='Logcat Output:')
logcat_label.pack()
logcat_text = tk.Text(root, height=10, width=50)
logcat_text.pack()
clear_button = tk.Button(root, text='Clear Logcat', command=clear_logcat)
clear_button.pack()
root.mainloop()
