from collections import Counter

import numpy as np
from scipy.stats import entropy


def calculate_entropy(string):
    if not string:
        return 0
    char_counts = Counter(string)
    text_entropy = entropy(list(char_counts.values()), base=np.e)
    return text_entropy


def metadata_entropy_count(metadata):
    entropy = 0
    for entry in metadata:
        if entry:
            entropy += calculate_entropy(entry)
    return entropy


def metadata_path_count(metadata):
    path_count = 0
    for entry in metadata:
        if entry:
            if "\\" in entry or "/" in entry:
                path_count += 1
    return path_count


def metadata_digit_count(metadata):
    digit_count = 0
    for entry in metadata:
        if entry:
            digit_count += sum(1 for char in entry if char.isdigit())
    return digit_count


def metadata_char_count(metadata):
    special_char_count = 0
    special_chars = set("!@#$%^&*()-_=+[{]};:'\",<.>/?\\|")

    for entry in metadata:
        if entry:
            special_char_count += sum(1 for char in entry if char in special_chars)
    return special_char_count


def metadata_char_count(metadata):
    special_char_count = 0
    special_chars = set("!@#$%^&*()-_=+[{]};:'\",<.>/?\\|")

    for entry in metadata:
        if entry:
            special_char_count += sum(1 for char in entry if char in special_chars)
    return special_char_count


def process_metadata_format(metadata_format):
    if not metadata_format:
        return 0

    path_count = 0
    total_entropy = 0
    special_char_count = 0
    digit_count = 0
    valid_entries = 0

    special_chars = set("!@#$%^&*()-_=+[{]};:'\",<.>/?\\|")

    for entry in metadata_format:
        if entry:
            valid_entries += 1

            if "\\" in entry or "/" in entry:
                path_count += 1

            total_entropy += calculate_entropy(entry)

            special_char_count += sum(1 for char in entry if char in special_chars)
            digit_count += sum(1 for char in entry if char.isdigit())

    avg_entropy = total_entropy / valid_entries if valid_entries > 0 else 0

    combined_score = (path_count + avg_entropy + special_char_count + digit_count) / (valid_entries + 1)

    return combined_score
