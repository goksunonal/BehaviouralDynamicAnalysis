import zipfile

import requests
import os

BASE_URL = 'http://192.168.56.105:5000'

def set_base_url(url):
    global BASE_URL
    BASE_URL = f'http://{url}:5000'


def get_next_file():
    url = f"{BASE_URL}/get_next_file"
    response = requests.get(url)
    return response.json()['file']


def upload_log_folder(filename, folder_path):
    url = f"{BASE_URL}/upload_log"

    temp_zipfile = f'{filename}.zip'  # Temporary zip file path

    try:
        # Create a zip file of the folder contents
        with zipfile.ZipFile(temp_zipfile, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, folder_path))

        # Upload the zip file
        with open(temp_zipfile, 'rb') as f:
            files = {'log': f}
            response = requests.post(url, files=files)

        os.remove(temp_zipfile)

        return response.json()

    except FileNotFoundError as e:
        print(f'Error: File or directory not found - {e}')
    except zipfile.BadZipFile as e:
        print(f'Error: Bad zip file - {e}')
    except requests.RequestException as e:
        print(f'Error: Request failed - {e}')
    except Exception as e:
        print(f'Error: {e}')

    return None


def get_logs():
    url = f"{BASE_URL}/get_logs"
    response = requests.get(url)
    return response.json()
