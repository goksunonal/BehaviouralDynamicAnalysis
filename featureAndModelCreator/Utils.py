import re
from collections import Counter

from scipy.stats import entropy


def calculate_presence_ratio(series):
    return series.apply(lambda x: 1 if x > 0 else 0).sum() / len(series)


def extract_file_version_features(version):
    features = {}

    version_parts = re.split(r'[.,\s\(\)]+', version)

    version_parts = [part for part in version_parts if part]

    features['version_length'] = len(version_parts)

    non_numeric = any(not part.isdigit() for part in version_parts)
    features['has_non_numeric'] = int(non_numeric)

    build_info = bool(re.search(r'build|winbuild', version.lower()))
    features['has_build_info'] = int(build_info)

    numeric_parts = [int(part) for part in version_parts if part.isdigit()]
    if numeric_parts:
        features['max_version_part'] = max(numeric_parts)
        features['min_version_part'] = min(numeric_parts)
    else:
        features['max_version_part'] = 0
        features['min_version_part'] = 0

    features['has_v_prefix'] = int(version.startswith('v'))

    features['is_na'] = int(version.strip().lower() == 'n/a')

    return features


suspicious_keywords = ['install', 'update', 'temp', 'system', 'netstat', 'config', 'run', 'cmd', 'setup', 'service']


def extract_filename_features(filename):
    features = {}

    extension = filename.split('.')[-1] if '.' in filename else ''
    if extension != 'exe':
        features['non_exe_file_extension'] = 1.0
    else:
        features['non_exe_file_extension'] = 0.0

    features['filename_length'] = len(filename)

    uppercase_count = sum(1 for char in filename if char.isupper())
    lowercase_count = sum(1 for char in filename if char.islower())
    features['upper_lower_ratio'] = uppercase_count / (lowercase_count + 1)

    non_alphanumeric_count = len(re.findall(r'[^a-zA-Z0-9]', filename))
    features['non_alphanumeric_count'] = non_alphanumeric_count

    features['has_suspicious_keyword'] = int(any(kw in filename.lower() for kw in suspicious_keywords))

    numeric_count = sum(1 for char in filename if char.isdigit())
    features['numeric_count'] = numeric_count

    if len(filename) > 0:
        char_counts = Counter(filename)
        probs = [count / len(filename) for count in char_counts.values()]
        features['filename_entropy'] = entropy(probs)
    else:
        features['filename_entropy'] = 0

    return features
