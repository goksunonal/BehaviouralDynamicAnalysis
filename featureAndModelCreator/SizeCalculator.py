import os

malware_log_dir = "malware_log_path"
benign_log_dir = "benign_log_path"


def get_total_csv_size(directory):
    total_size = 0
    count = 0

    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.pcap'):
                file_path = os.path.join(root, filename)

                total_size += os.path.getsize(file_path)

    return total_size


total_csv_size = get_total_csv_size(malware_log_dir) / 2854
total_csv_size_kb = total_csv_size / 1024
total_csv_size_mb = total_csv_size / (1024 * 1024)

total_csv_size2 = get_total_csv_size(benign_log_dir) / 4745
total_csv_size2_kb = total_csv_size2 / 1024
total_csv_size2_mb = total_csv_size2 / (1024 * 1024)

print(f"Total size of all CSV files: {total_csv_size} bytes")
print(f"Total size of all CSV files: {total_csv_size_kb} kilobytes")
print(f"Total size of all CSV files: {total_csv_size_mb} megabytes")

print("---------")
print(f"Total size of all CSV files: {total_csv_size2} bytes")
print(f"Total size of all CSV files: {total_csv_size2_kb} kilobytes")
print(f"Total size of all CSV files: {total_csv_size2_mb} megabytes")
