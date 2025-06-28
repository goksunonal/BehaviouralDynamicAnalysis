import re
from collections import Counter

import numpy as np
from scipy.stats import entropy


def load_word_list(file_path='/usr/share/dict/words'):
    with open(file_path, 'r') as f:
        words = set(word.strip().lower() for word in f)
    return words


word_list = load_word_list()


def calculate_word_count(text):
    words = re.findall(r'\b\w+\b', text)
    return len(words)


def calculate_digit_proportion(text):
    total_chars = len(text)
    if total_chars == 0:
        return 0
    digit_count = len(re.findall(r'\d', text))
    return digit_count / total_chars


def calculate_capital_proportion(text):
    words = re.findall(r'\b[A-Za-z]+\b', text)
    if len(words) == 0:
        return 0
    capital_words = [word for word in words if word.isupper()]
    return len(capital_words) / len(words)


def calculate_symbol_proportion(text):
    total_chars = len(text)
    if total_chars == 0:
        return 0
    symbol_count = len(re.findall(r'[^\w\s]', text))
    return symbol_count / total_chars


def calculate_entropy(text):
    char_counts = Counter(text)
    text_entropy = entropy(list(char_counts.values()), base=2)
    word_count = len(re.findall(r'\b\w+\b', text))
    return text_entropy / (word_count + 1)


def check_dictionary_words(text):
    words_in_text = re.findall(r'\b\w+\b', text.lower())

    count = sum(1 if word not in word_list else 0 for word in words_in_text)
    return count / len(words_in_text) if words_in_text else 0


def detect_random_patterns(text):
    non_vowel_pattern = r'[^AEIOUaeiou]{4,}'
    has_non_vowel_sequence = bool(re.search(non_vowel_pattern, text))

    digit_pattern = r'\d{6}'
    has_digit_sequence = bool(re.search(digit_pattern, text))

    symbol_pattern = r'[^\w\s]{3,}'
    has_symbol_pattern = bool(re.search(symbol_pattern, text))

    return has_non_vowel_sequence or has_digit_sequence or has_symbol_pattern


def calculate_entropy_base_e(text):
    char_counts = Counter(text)
    text_entropy = entropy(list(char_counts.values()), base=np.e)
    word_count = len(re.findall(r'\b[A-Za-z]+\b', text))
    return text_entropy / (word_count + 1)


def normalize_by_text_length(feature_value, text):
    text_length = len(re.findall(r'\b\w+\b', text))
    return feature_value / (text_length + 1)


def composite_text_complexity_score(word_count,
                                    digit_proportion,
                                    capital_proportion,
                                    symbol_proportion,
                                    dictionary_word_proportion,
                                    random_pattern_flag):
    combined_score = (word_count * 0.2 +
                      digit_proportion * 0.5 +
                      capital_proportion * 0.7 +
                      symbol_proportion * 0.8 +
                      dictionary_word_proportion * 0.4 +
                      random_pattern_flag * 1)

    return combined_score
