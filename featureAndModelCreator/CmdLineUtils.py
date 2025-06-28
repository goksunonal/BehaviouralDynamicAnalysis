import re
from collections import Counter

suspicious_keywords = [
    'schtasks', 'msedge.exe', 'powershell', 'cmd.exe', 'vbs', 'wscript', 'cscript', 'ps1', '/c', '/b', '/s',
    '-EncodedCommand', '-nop', '-w hidden', '%TEMP%', 'AppData', 'Startup', 'rundll32.exe'
]


def extract_command_line_features(command):
    tokens = command.split()
    unique_suspicious_keyword = set()
    keyword_counts = Counter(token.lower() for token in tokens if token.lower() in suspicious_keywords)
    for keyword, count in keyword_counts.items():
        unique_suspicious_keyword.add(keyword)

    suspicious_key_count = len(unique_suspicious_keyword)
    commandLength = len(command)
    num_tokens = len(tokens)
    flag_count = len([token for token in tokens if token.startswith('--')])
    extensions = {re.search(r'\.(\w+)', token.lower()).group(1) for token in tokens if re.search(r'\.(\w+)', token)}
    unique_extension_count = len(extensions)
    encoded_command = int(bool(re.search(r'-EncodedCommand', command)))
    obfuscation_flags = int(bool(re.search(r'-nop|-w hidden', command)))
    temp_directory = int('Temp' in command)
    appdata_directory = int('AppData' in command)
    num_uppercase = sum(1 for char in command if char.isupper())
    num_digits = sum(1 for char in command if char.isdigit())
    num_special_chars = sum(1 for char in command if not char.isalnum() and char != ' ')

    return (suspicious_key_count, commandLength, num_tokens, flag_count, unique_extension_count, encoded_command,
            obfuscation_flags, temp_directory, appdata_directory, num_uppercase, num_digits, num_special_chars)
