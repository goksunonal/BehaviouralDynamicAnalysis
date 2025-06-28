import csv
import json
import os
from json import JSONDecodeError
from tkinter import Tk, filedialog
from tkinter import simpledialog


def flatten_json(json_data, parent_key='', separator='_'):
    items = {}
    for key, value in json_data.items():
        new_key = parent_key + separator + key if parent_key else key
        if "EventData" in parent_key:
            return items
        if isinstance(value, dict):
            items.update(flatten_json(value, new_key, separator))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if "{" in str(item) and "}" in str(item):
                    items.update(flatten_json(item, f"{new_key}_{i}", separator))
                else:
                    items[new_key] = ', '.join(map(str, value))
        else:
            items[new_key] = value
    return items


def operate_file(csv_file):
    flattened_rows = []
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    for row in rows:
        if "Event" in row and row["Event"]:
            raw_value = row["Event"]
            try:
                json_data = json.loads(raw_value)
                event_data = json_data.get("Event", []).get("EventData", [])
                flattened_data = flatten_json(json_data)
                if isinstance(event_data, dict):
                    data_list = event_data.get("Data", [])
                    binary = event_data.get("Binary", "")
                    if binary is not None and binary != "":
                        flattened_data["binary"] = binary
                    if data_list is not None:
                        if "@Name" in data_list:
                            flattened_data[data_list["@Name"]] = data_list["#text"]
                        else:
                            for i, item in enumerate(data_list):
                                if isinstance(item, dict) and "@Name" in item and "#text" in item:
                                    flattened_data[item["@Name"]] = item["#text"]
                                else:
                                    if item is not None and len(item) > 1:
                                        print(f"Invalid Data format in {csv_file}:")
                                        flattened_data["metadata_format"] = str(data_list)

                flattened_rows.append(flattened_data)
            except JSONDecodeError:
                print(f"Invalid JSON in {csv_file}")

    return flattened_rows


def write_csv(output_file, all_fieldnames, all_flattened_rows):
    with open(output_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=all_fieldnames)
        writer.writeheader()
        writer.writerows(all_flattened_rows)


def combine_csvs(input_dir, output_file):
    all_flattened_rows = []
    all_fieldnames = set()

    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.endswith('.csv'):
                file_path = os.path.join(root, file)
                print(f"Processing {file_path}...")
                flattened_rows = operate_file(file_path)
                all_flattened_rows.extend(flattened_rows)
                for row in flattened_rows:
                    all_fieldnames.update(row.keys())

    all_fieldnames = list(all_fieldnames)

    write_csv(output_file, all_fieldnames, all_flattened_rows)


def select_directory_and_combine():
    root = Tk()
    root.withdraw()
    input_directory = filedialog.askdirectory(title="Select Input Directory")
    if input_directory:
        category_name = simpledialog.askstring("Category Name", "Enter the category name for the output CSV file:")
        if category_name:
            output_csv = category_name + '-combined_data.csv'
            combine_csvs(input_directory, output_csv)
            print(f"Data combined and saved to {output_csv}")
        else:
            print("Category name is required.")
    else:
        print("No directory selected.")
