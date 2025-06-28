import os
from ast import literal_eval
from collections import defaultdict, Counter

import numpy as np
import pandas as pd
from scipy.stats import entropy, kurtosis

from CmdLineUtils import extract_command_line_features
from EventIdAnalyzer import extract_event_category_features, \
    calculate_uncategorized_event_count
from FlattenJson import operate_file
from MetadataCalculator import metadata_char_count, \
    metadata_digit_count, metadata_path_count, metadata_entropy_count
from SuspiciousUniqueFeatureCounter import calculate_unique_suspicious_features
from Utils import extract_file_version_features, extract_filename_features
from WordScoreCalculator import calculate_word_count, calculate_digit_proportion, \
    calculate_capital_proportion, calculate_symbol_proportion, calculate_entropy, check_dictionary_words, \
    detect_random_patterns, normalize_by_text_length, composite_text_complexity_score

admin_users = {'Administrator', 'SYSTEM', 'NT AUTHORITY\\SYSTEM'}
service_accounts = {'NT AUTHORITY\\NETWORK SERVICE', 'NT AUTHORITY\\LOCAL SERVICE', 'NETWORK SERVICE'}
common_processes = {'svchost.exe', 'explorer.exe', 'cmd.exe', 'powershell.exe'}
logons = set()
logons2 = set()
flags = {'0x20000', '0x20040'}

read_event_flag = '4656'
write_event_flag = '4658'

high_privilege_levels = {'System', 'High', 'Administrator'}

running_time = 18

file_count = 0

try_count = 0


def check_user_privileges(user_info):
    if user_info in admin_users:
        return 'admin'
    elif user_info in service_accounts:
        return 'service'
    elif 'S-1-' in user_info:
        return 'sid'
    return 'normal_user'


def calculate_extension_changes(file_paths):
    extension_changes = 0
    seen_extensions = set()
    for path in file_paths:
        ext = os.path.splitext(path)[1][1:].lower()
        if ext in seen_extensions:
            extension_changes += 1
        seen_extensions.add(ext)
    return extension_changes


def calculate_high_privilege_executions(user_sessions):
    high_privilege_users = {'SYSTEM', 'Administrator'}
    high_privilege_execs = sum(1 for user in user_sessions if user in high_privilege_users)
    return high_privilege_execs


def calculate_file_read_write_ratio(event_counts):
    read_count = event_counts.get('4656', 0)
    write_count = event_counts.get('4658', 0)
    return read_count / (write_count + 1)


def calculate_process_relaunch(process_ids, event_times):
    process_relaunch_count = 0
    if len(event_times) > 1:
        for i in range(len(event_times) - 1):
            time_diff = (pd.Timestamp(event_times[i + 1]) - pd.Timestamp(event_times[i])).total_seconds()
            if time_diff < 2:
                process_relaunch_count += 1
    return process_relaunch_count


process_injection_event_ids = {'8'}
registry_modification_event_ids = {'12'}
dll_injection_event_ids = {'7'}
file_handle_creation_event_ids = {'4656'}
file_handle_closure_event_ids = {'4658'}

suspicious_directories = [
    'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\',
    'C:\\ProgramData\\',
    'C:\\Users\\Administrator\\',
    'C:\\tfsjike\\',
    'C:\\mshyperbrowserDhcp\\',
    'C:\\gijbzzhxajxjk\\',
    'C:\\Blockprovider\\',
    'C:\\BlockproviderComponentweb\\',
    'C:\\Recovery\\WindowsRE\\',
    'C:\\Program Files\\Common Files\\',
    'C:\\ProgramData\\',
    'C:\\Boot\\',
    'C:\\containersaves\\',
    'C:\\runtimebrokermonitor\\'
]
suspicious_extensions = ['exe', 'dll', 'sys', 'bat', 'vbs', 'ps1', 'scr']

non_process_file = 0


def isValidValue(value=None):
    return value is not None and value != '-'


def process_folder(log_dir, is_malware):
    global file_count, non_process_file
    all_files_data = []

    for exe_folder in os.listdir(log_dir):
        exe_path = os.path.join(log_dir, exe_folder)
        file_count += 1
        print(f'File Count: {file_count}')
        if os.path.isdir(exe_path):

            feature_dict = extract_features_for_exe(exe_path, is_malware, exe_folder)

            feature_dict['folder_name'] = exe_folder
            feature_dict['Is_Malware'] = is_malware
            if feature_dict['Total_Number_of_Events'] * running_time > 2:
                feature_dict.pop('Total_Number_of_Events')
                all_files_data.append(feature_dict)
            else:
                non_process_file += 1
    return pd.DataFrame(all_files_data)


new_features = [
    "Event_UserData_LogFileCleared_Channel", "param1", "Event_UserData_RmSessionEvent_UTCStartTime", "ApplicationPath",
    "ProcessImageNameBuffer", "Event_UserData_CompatibilityFixEvent_FixID"
]


def extract_features_for_exe(exe_folder, is_malware, exe_net_path):
    global read_event_flag, write_event_flag
    event_counts = defaultdict(int)
    all_event_times = []
    file_paths = set()
    process_ids = set()
    parent_processes = []
    child_processes = set()
    unique_event_ids = set()
    event_record_ids = set()
    file_extensions = set()
    total_command_line_args = set()
    hashes = defaultdict(set)
    encoded_command_count = 0.0
    interface_guid_count = 0.0
    subject_event_count = 0.0
    caption_count = 0.0

    error_code_count = 0.0
    process_guid_count = []
    metadata_entropy = 0.0
    metadata_path = 0.0
    metadata_digit = 0.0
    metadata_char = 0.0

    hc_state_count = []
    message_count = []
    utc_times = 0.0

    source_digit_proportion = 0.0
    source_capital_proportion = 0.0
    source_symbol_proportion = 0.0
    source_entropy_value = 0.0
    source_dictionary_word_proportion = 0.0
    source_random_pattern_flag = 0.0
    source_normalized_word_count = 0.0

    rule_names_normalized_word_count = 0.0
    rule_names_digit_proportion = 0.0
    rule_names_capital_proportion = 0.0
    rule_names_symbol_proportion = 0.0
    rule_names_entropy_value = 0.0
    rule_names_dictionary_word_proportion = 0.0
    rule_names_random_pattern_flag = 0.0

    event_file_versions = []
    file_version_length = 0.0
    file_version_non_numeric = 0.0
    file_version_build_info = 0.0
    file_version_max = 0.0
    file_version_min = 0.0
    file_version_v_prefix = 0.0
    file_version_is_na = 0.0

    suspicious_dir_count = 0.0
    burst_event_count = set()
    process_paths = set()
    current_dir_paths = set()

    opcodes = []
    tasks = []
    operationIds = []
    authentication_event_count = 0.0
    privilege_event_count = 0.0
    process_creation_event_count = 0.0
    security_event_count = 0.0
    crash_event_count = 0.0
    unique_thread_id = []
    high_privilege_integrity_count = 0.0

    service_digit_proportion = 0.0
    service_capital_proportion = 0.0
    service_symbol_proportion = 0.0
    service_entropy_value = 0.0
    service_dictionary_word_proportion = 0.0
    service_random_pattern_flag = 0.0
    service_normalized_word_count = 0.0
    service_normalized_avg_word_length = 0.0

    description_digit_proportion = 0.0
    description_capital_proportion = 0.0
    description_symbol_proportion = 0.0
    description_entropy_value = 0.0
    description_dictionary_word_proportion = 0.0
    description_random_pattern_flag = 0.0
    description_normalized_word_count = 0.0
    description_normalized_avg_word_length = 0.0

    script_blocks = 0.0

    original_file_ext = 0.0
    original_file_length = 0.0
    original_file_lower_ratio = 0.0
    original_file_alpha_numeric = 0.0
    original_file_keyword = 0.0
    original_file_numeric = 0.0
    original_file_entropy = 0.0

    permission_flag_counts = 0.0

    company_digit_proportion = 0.0
    company_capital_proportion = 0.0
    company_symbol_proportion = 0.0
    company_entropy_value = 0.0
    company_dictionary_word_proportion = 0.0
    company_random_pattern_flag = 0.0
    company_normalized_word_count = 0.0
    company_normalized_avg_word_length = 0.0

    product_digit_proportion = 0.0
    product_capital_proportion = 0.0
    product_symbol_proportion = 0.0
    product_entropy_value = 0.0
    product_dictionary_word_proportion = 0.0
    product_random_pattern_flag = 0.0
    product_normalized_word_count = 0.0
    product_normalized_avg_word_length = 0.0

    unique_line_number = []
    read_count = 0.0
    fileCount_count = 0.0
    write_count = 0.0
    proc_create_count = 0.0
    unique_suspicious_fields = set()

    keywords = []
    system_provider_names = []

    command_line_key_count = 0.0
    command_line_cmd_length = 0.0
    command_line_num_tokens = 0.0
    command_line_flag_count = 0.0
    command_line_extension_count = 0.0
    command_line_encoded_command = 0.0
    command_line_obfuscation_flags = 0.0
    command_line_temp_directory = 0.0
    command_line_appdata_directory = 0.0
    command_line_num_uppercase = 0.0
    command_line_num_digits = 0.0
    command_line_num_special_chars = 0.0
    new_features_count = {name: [] for name in new_features}

    admin_users = 0
    other_users = 0
    payload_size = 0
    event_type_count = set()

    for root, dirs, files in os.walk(exe_folder):
        for file in files:
            if file.endswith(".csv"):
                file_path = os.path.join(root, file)
                events = operate_file(file_path)

                for event in events:
                    process_event(event, event_counts, all_event_times, file_paths, process_ids, parent_processes,
                                  unique_event_ids,
                                  total_command_line_args, burst_event_count, process_paths,
                                  current_dir_paths, child_processes, exe_net_path)

                    event_type = event.get('Event_System_EventID')
                    if isValidValue(event_type):
                        event_type_count.add(event_type)
                        if event_type == read_event_flag:
                            read_count += 1
                        if event_type == write_event_flag:
                            write_count += 1
                    event_type_array = extract_event_category_features(event_type)
                    for type in event_type_array:
                        if isValidValue(type):
                            value = event_type_array[type]
                            if type == 'Authentication':
                                authentication_event_count += value
                            if type == 'Privilege_Escalation':
                                privilege_event_count += value
                            if type == 'Security_Policy_Change':
                                security_event_count += value
                            if type == 'Process_Creation':
                                process_creation_event_count += value
                            if type == 'Crash_or_Failure':
                                crash_event_count += value

                    for feature in new_features:
                        feature_value = event.get(feature)
                        if feature_value:
                            new_features_count[feature].append(feature_value)
                    guid = event.get('InterfaceGuid')
                    if isValidValue(guid):
                        interface_guid_count += 1

                    process_guid = event.get('ProcessGuid')
                    if isValidValue(process_guid):
                        process_guid_count.append(process_guid)

                    opcode = event.get('Event_System_Opcode')
                    task = event.get('Event_System_Task')
                    if isValidValue(opcode):
                        opcodes.append(opcode)
                    if isValidValue(task):
                        tasks.append(task)
                    state_id = event.get('hc_stateid')
                    message = event.get('Message')
                    source = event.get('Source')
                    file_version = event.get('FileVersion')
                    if isValidValue(state_id):
                        hc_state_count.append(state_id)
                    if isValidValue(message):
                        message_count.append(message)
                    if isValidValue(source):
                        word_count = calculate_word_count(source)
                        source_digit_proportion += calculate_digit_proportion(source)
                        source_capital_proportion += calculate_capital_proportion(source)
                        source_symbol_proportion += calculate_symbol_proportion(source)
                        source_entropy_value += calculate_entropy(source)
                        source_dictionary_word_proportion += check_dictionary_words(source)
                        source_random_pattern_flag += detect_random_patterns(source)
                        source_normalized_word_count += normalize_by_text_length(word_count, source)
                    if isValidValue(file_version):
                        event_file_versions.append(file_version)
                        file_version_features = extract_file_version_features(file_version)
                        file_version_length += file_version_features['version_length']
                        file_version_non_numeric += file_version_features['has_non_numeric']
                        file_version_build_info += file_version_features['has_build_info']
                        file_version_max += file_version_features['max_version_part']
                        file_version_min += file_version_features['min_version_part']
                        file_version_v_prefix += file_version_features['has_v_prefix']
                        file_version_is_na += file_version_features['is_na']
                    lineNumber = event.get('Line Number')
                    if isValidValue(lineNumber):
                        unique_line_number.append(int(lineNumber))

                    file_hash = event.get('Hashes')
                    file_path = event.get('Image')
                    if isValidValue(file_hash):
                        hashes[file_hash].add(file_path)

                    process_command_line = event.get('ProcessCommandLine')
                    command_line = event.get('CommandLine')
                    command = event.get('Command')
                    parent_command_line = event.get('ParentCommandLine')
                    if isValidValue(process_command_line):
                        (command_line_key_count1, command_line_cmd_length1, command_line_num_tokens1,
                         command_line_flag_count1,
                         command_line_extension_count1, command_line_encoded_command1,
                         command_line_obfuscation_flags1, command_line_temp_directory1,
                         command_line_appdata_directory1, command_line_num_uppercase1, command_line_num_digits1,
                         command_line_num_special_chars1) = extract_command_line_features(process_command_line)
                        command_line_key_count += command_line_key_count1
                        command_line_cmd_length += command_line_cmd_length1
                        command_line_num_tokens += command_line_num_tokens1
                        command_line_flag_count += command_line_flag_count1
                        command_line_extension_count += command_line_extension_count1
                        command_line_encoded_command += command_line_encoded_command1
                        command_line_obfuscation_flags += command_line_obfuscation_flags1
                        command_line_temp_directory += command_line_temp_directory1
                        command_line_appdata_directory += command_line_appdata_directory1
                        command_line_num_uppercase += command_line_num_uppercase1
                        command_line_num_digits += command_line_num_digits1
                        command_line_num_special_chars += command_line_num_special_chars1
                    if isValidValue(command_line):
                        (command_line_key_count1, command_line_cmd_length1, command_line_num_tokens1,
                         command_line_flag_count1,
                         command_line_extension_count1, command_line_encoded_command1,
                         command_line_obfuscation_flags1, command_line_temp_directory1,
                         command_line_appdata_directory1, command_line_num_uppercase1, command_line_num_digits1,
                         command_line_num_special_chars1) = extract_command_line_features(command_line)
                        command_line_key_count += command_line_key_count1
                        command_line_cmd_length += command_line_cmd_length1
                        command_line_num_tokens += command_line_num_tokens1
                        command_line_flag_count += command_line_flag_count1
                        command_line_extension_count += command_line_extension_count1
                        command_line_encoded_command += command_line_encoded_command1
                        command_line_obfuscation_flags += command_line_obfuscation_flags1
                        command_line_temp_directory += command_line_temp_directory1
                        command_line_appdata_directory += command_line_appdata_directory1
                        command_line_num_uppercase += command_line_num_uppercase1
                        command_line_num_digits += command_line_num_digits1
                        command_line_num_special_chars += command_line_num_special_chars1
                    if isValidValue(command):
                        (command_line_key_count1, command_line_cmd_length1, command_line_num_tokens1,
                         command_line_flag_count1,
                         command_line_extension_count1, command_line_encoded_command1,
                         command_line_obfuscation_flags1, command_line_temp_directory1,
                         command_line_appdata_directory1, command_line_num_uppercase1, command_line_num_digits1,
                         command_line_num_special_chars1) = extract_command_line_features(command)
                        command_line_key_count += command_line_key_count1
                        command_line_cmd_length += command_line_cmd_length1
                        command_line_num_tokens += command_line_num_tokens1
                        command_line_flag_count += command_line_flag_count1
                        command_line_extension_count += command_line_extension_count1
                        command_line_encoded_command += command_line_encoded_command1
                        command_line_obfuscation_flags += command_line_obfuscation_flags1
                        command_line_temp_directory += command_line_temp_directory1
                        command_line_appdata_directory += command_line_appdata_directory1
                        command_line_num_uppercase += command_line_num_uppercase1
                        command_line_num_digits += command_line_num_digits1
                        command_line_num_special_chars += command_line_num_special_chars1
                    if isValidValue(parent_command_line):
                        (command_line_key_count1, command_line_cmd_length1, command_line_num_tokens1,
                         command_line_flag_count1,
                         command_line_extension_count1, command_line_encoded_command1,
                         command_line_obfuscation_flags1, command_line_temp_directory1,
                         command_line_appdata_directory1, command_line_num_uppercase1, command_line_num_digits1,
                         command_line_num_special_chars1) = extract_command_line_features(parent_command_line)
                        command_line_key_count += command_line_key_count1
                        command_line_cmd_length += command_line_cmd_length1
                        command_line_num_tokens += command_line_num_tokens1
                        command_line_flag_count += command_line_flag_count1
                        command_line_extension_count += command_line_extension_count1
                        command_line_encoded_command += command_line_encoded_command1
                        command_line_obfuscation_flags += command_line_obfuscation_flags1
                        command_line_temp_directory += command_line_temp_directory1
                        command_line_appdata_directory += command_line_appdata_directory1
                        command_line_num_uppercase += command_line_num_uppercase1
                        command_line_num_digits += command_line_num_digits1
                        command_line_num_special_chars += command_line_num_special_chars1
                    script_block = event.get('ScriptBlockText')
                    if isValidValue(script_block):
                        script_blocks += 1.0

                    integrity_level = event.get('IntegrityLevel')
                    if isValidValue(integrity_level) and integrity_level in high_privilege_levels:
                        high_privilege_integrity_count += 1

                    utc_time = event.get('UtcTime')
                    if isValidValue(utc_time):
                        utc_times += 1.0

                    subjectUserId = event.get('SubjectUserSid')
                    if isValidValue(subjectUserId):
                        subject_event_count += 1
                    thread = event.get('Event_System_Execution_@ThreadID')
                    if isValidValue(thread):
                        unique_thread_id.append(thread)

                    rule = event.get('RuleName')
                    if isValidValue(rule):
                        word_count = calculate_word_count(rule)
                        rule_names_digit_proportion += calculate_digit_proportion(rule)
                        rule_names_capital_proportion += calculate_capital_proportion(rule)
                        rule_names_symbol_proportion += calculate_symbol_proportion(rule)
                        rule_names_entropy_value += calculate_entropy(rule)
                        rule_names_dictionary_word_proportion += check_dictionary_words(rule)
                        rule_names_random_pattern_flag += detect_random_patterns(rule)
                        rule_names_normalized_word_count += normalize_by_text_length(word_count, rule)

                    operational_process_id = event.get('Event_UserData_Operation_StartedOperational_ProcessID')
                    if isValidValue(operational_process_id):
                        operationIds.append(operational_process_id)
                    provider = event.get('Event_System_Provider_@EventSourceName')
                    keyword = event.get('Event_System_Keywords')
                    if isValidValue(provider):
                        system_provider_names.append(provider)
                    if isValidValue(keyword):
                        keywords.append(keyword)

                    file_path = event.get('Image')
                    if isValidValue(file_path):
                        for dir in suspicious_directories:
                            if dir in file_path:
                                suspicious_dir_count += 1
                    service = event.get('ServiceName')
                    if isValidValue(service):
                        word_count = calculate_word_count(service)
                        service_digit_proportion += calculate_digit_proportion(service)
                        service_capital_proportion += calculate_capital_proportion(service)
                        service_symbol_proportion += calculate_symbol_proportion(service)
                        service_entropy_value += calculate_entropy(service)
                        service_dictionary_word_proportion += check_dictionary_words(service)
                        service_random_pattern_flag += detect_random_patterns(service)
                        service_normalized_word_count += normalize_by_text_length(word_count, service)
                    description = event.get('Description')
                    company = event.get('Company')
                    product = event.get('Product')
                    if isValidValue(description):
                        word_count = calculate_word_count(description)
                        description_digit_proportion += calculate_digit_proportion(description)
                        description_capital_proportion += calculate_capital_proportion(description)
                        description_symbol_proportion += calculate_symbol_proportion(description)
                        description_entropy_value += calculate_entropy(description)
                        description_dictionary_word_proportion += check_dictionary_words(description)
                        description_random_pattern_flag += detect_random_patterns(description)
                        description_normalized_word_count += normalize_by_text_length(word_count, description)
                    originalFile = event.get('OriginalFileName')
                    if isValidValue(originalFile):
                        originalFileFeatures = extract_filename_features(originalFile)
                        original_file_ext += originalFileFeatures['non_exe_file_extension']
                        original_file_length += originalFileFeatures['filename_length']
                        original_file_lower_ratio += originalFileFeatures['upper_lower_ratio']
                        original_file_alpha_numeric += originalFileFeatures['non_alphanumeric_count']
                        original_file_keyword += originalFileFeatures['has_suspicious_keyword']
                        original_file_numeric += originalFileFeatures['numeric_count']
                        original_file_entropy += originalFileFeatures['filename_entropy']
                    if isValidValue(company):
                        word_count = calculate_word_count(company)
                        company_digit_proportion += calculate_digit_proportion(company)
                        company_capital_proportion += calculate_capital_proportion(company)
                        company_symbol_proportion += calculate_symbol_proportion(company)
                        company_entropy_value += calculate_entropy(company)
                        company_dictionary_word_proportion += check_dictionary_words(company)
                        company_random_pattern_flag += detect_random_patterns(company)
                        company_normalized_word_count += normalize_by_text_length(word_count, company)
                    if isValidValue(product):
                        word_count = calculate_word_count(product)
                        product_digit_proportion += calculate_digit_proportion(product)
                        product_capital_proportion += calculate_capital_proportion(product)
                        product_symbol_proportion += calculate_symbol_proportion(product)
                        product_entropy_value += calculate_entropy(product)
                        product_dictionary_word_proportion += check_dictionary_words(product)
                        product_random_pattern_flag += detect_random_patterns(product)
                        product_normalized_word_count += normalize_by_text_length(word_count, product)
                    fileCount = event.get('fileCount')
                    if isValidValue(fileCount):
                        fileCount_count += 1
                    flag = event.get('Flags')
                    if isValidValue(flag) and flag in flags:
                        permission_flag_counts += 1
                    size = event.get('PayloadSize')
                    if isValidValue(size):
                        payload_size += int(size)
                    user = event.get('User')
                    if isValidValue(user):
                        if check_user_privileges(user) == 'admin':
                            admin_users += 1
                        else:
                            other_users += 1
                    errorCode = event.get('Error Code')
                    if isValidValue(errorCode):
                        error_code_count += 1

                    caption = event.get('Caption')
                    if isValidValue(caption):
                        if exe_net_path not in caption:
                            caption_count += 1
                    event_record_id = event.get('Event_System_EventRecordID')
                    if isValidValue(event_record_id):
                        event_record_ids.add(event_record_id)

                    metadata = event.get('metadata_format')
                    if isValidValue(metadata):
                        array = literal_eval(metadata)
                        metadata_entropy += metadata_entropy_count(array)
                        metadata_path += metadata_path_count(array)
                        metadata_digit += metadata_digit_count(array)
                        metadata_char += metadata_char_count(array)
                    unique_fields = calculate_unique_suspicious_features(event)
                    for field in unique_fields:
                        if isValidValue(field):
                            unique_suspicious_fields.add(field)

    feature_dict = calculate_statistical_features(event_counts, all_event_times, file_paths, process_ids,
                                                  parent_processes, child_processes, unique_event_ids,
                                                  file_extensions, total_command_line_args,
                                                  process_paths)

    total_events = sum(event_counts.values()) + 1

    service_proportion = composite_text_complexity_score(service_normalized_word_count,
                                                         service_digit_proportion,
                                                         service_capital_proportion,
                                                         service_symbol_proportion,
                                                         service_dictionary_word_proportion,
                                                         service_random_pattern_flag)

    feature_dict['Service_Proportion'] = service_proportion / total_events
    feature_dict['Service_Entropy'] = service_entropy_value / total_events
    feature_dict['Auth_Event_Ratio'] = authentication_event_count / total_events
    feature_dict['Privilege_Event_Ratio'] = privilege_event_count / total_events
    feature_dict['Subject_Event_Ratio'] = subject_event_count / total_events
    feature_dict['Security_Event_Ratio'] = security_event_count / total_events

    feature_dict['Crash_Event_Ratio'] = crash_event_count / total_events
    feature_dict['Uncategorized_Event_Ratio'] = calculate_uncategorized_event_count(event_type_count) / total_events
    feature_dict['Interface_Guid_Ratio'] = interface_guid_count / total_events
    feature_dict['Caption_Ratio'] = caption_count / total_events
    feature_dict['Suspicious_Directory_Count'] = suspicious_dir_count / total_events
    common_process_usage = sum(1 for path in file_paths if any(proc in path for proc in common_processes))
    feature_dict['Common_Process_Name_Usage'] = common_process_usage / total_events
    feature_dict['Process_Burstiness_Ratio'] = len(burst_event_count) / total_events

    feature_dict['Unique_File_Paths_Accessed'] = (len(set(file_paths))) / (total_events + 1)

    parent_processes_ratio = (len(set(parent_processes)) / total_events) + 1
    feature_dict['Parent_Process_Ratio'] = parent_processes_ratio / total_events
    feature_dict['Hash_Count'] = len(hashes.keys()) / total_events

    anomalies = sum(1 for paths in hashes.values() if paths and len(paths) > 1)
    feature_dict['Hash_Anomalies'] = anomalies / total_events
    feature_dict['Admin_User_Ratio'] = (admin_users + 1) / (admin_users + other_users + 1)
    feature_dict['Error_Code_Ratio'] = error_code_count / total_events
    feature_dict['Event_Record_Id_Ratio'] = len(event_record_ids) / total_events

    description_avg_proportion = composite_text_complexity_score(description_normalized_word_count,
                                                                 description_digit_proportion,
                                                                 description_capital_proportion,
                                                                 description_symbol_proportion,
                                                                 description_dictionary_word_proportion,
                                                                 description_random_pattern_flag) / total_events

    feature_dict['Original_File_Ext'] = original_file_ext / (total_events)
    feature_dict['Original_File_Lower'] = original_file_lower_ratio / (total_events)

    feature_dict['Original_File_Alpha_Numeric'] = (original_file_alpha_numeric) / (
        total_events)

    feature_dict['Original_File_Keyword'] = original_file_keyword / total_events
    feature_dict['Original_File_Numeric'] = original_file_numeric / total_events

    for feature in new_features:
        feature_dict[f'{feature}_Count'] = len(set(new_features_count[feature])) / total_events
    company_proportion = composite_text_complexity_score(company_normalized_word_count,
                                                         company_digit_proportion,
                                                         company_capital_proportion,
                                                         company_symbol_proportion,
                                                         company_dictionary_word_proportion,
                                                         company_random_pattern_flag) / total_events
    feature_dict['Unique_Process_Guid'] = len(set(process_guid_count)) / total_events
    feature_dict['Utc_Ratio'] = utc_times / total_events

    product_proportion = composite_text_complexity_score(product_normalized_word_count,
                                                         product_digit_proportion,
                                                         product_capital_proportion,
                                                         product_symbol_proportion,
                                                         product_dictionary_word_proportion,
                                                         product_random_pattern_flag)

    feature_dict['Desc_Proportion'] = description_avg_proportion / total_events
    feature_dict['Product_Proportion'] = product_proportion / total_events
    feature_dict['Company_Proportion'] = company_proportion / total_events

    feature_dict['Current_Directory_Ratio'] = len(current_dir_paths) / total_events
    feature_dict['Avg_Payload_Size'] = payload_size / total_events

    feature_dict['Avg_Metadata_Path'] = (metadata_path) / (total_events)
    feature_dict['Avg_Metadata_Entropy'] = (metadata_entropy + 1) / (total_events)
    feature_dict['Avg_Metadata_Char'] = (metadata_char) / (total_events)
    feature_dict['Avg_Metadata_Digit'] = (metadata_digit) / (total_events)

    feature_dict['Avg_Permission_Flag_Count'] = permission_flag_counts / total_events
    feature_dict['Unique_Suspicious_Fields_Ratio'] = len(unique_suspicious_fields) / total_events

    feature_dict['High_Privilege_Ratio'] = (privilege_event_count) / (total_events)

    feature_dict['Cmd_Key_Count'] = command_line_key_count / total_events
    feature_dict['Cmd_Flag_Count'] = command_line_flag_count / total_events

    feature_dict['Cmd_Dir_Temp'] = command_line_temp_directory / total_events
    feature_dict['Cmd_Dir_Appdata'] = command_line_appdata_directory / total_events

    feature_dict['Cmd_Num_Digits'] = command_line_num_digits / total_events

    feature_dict['Line_Numbers'] = len(set(unique_line_number)) / total_events
    feature_dict['Message_Count'] = (len(set(message_count))) / total_events

    feature_dict['Opcode_Entropy'] = entropy(pd.DataFrame(opcodes).value_counts(normalize=True))

    feature_dict['Keyword_Ratio'] = (len(set(keywords))) / total_events
    feature_dict['Task_Ratio'] = (len(set(tasks))) / total_events
    feature_dict['Thread_Id'] = (len(set(unique_thread_id))) / total_events

    feature_dict['Keyword_Entropy'] = entropy(pd.DataFrame(set(keywords)).value_counts(normalize=True))
    feature_dict['Task_Entropy'] = entropy(pd.DataFrame(set(tasks)).value_counts(normalize=True))

    feature_dict['HC_State_Ratio'] = (len(set(hc_state_count))) / total_events
    feature_dict['System_Provider_Ratio'] = (len(set(system_provider_names))) / total_events

    feature_dict['System_Provider_Entropy'] = entropy(
        pd.DataFrame(set(system_provider_names)).value_counts(normalize=True))
    feature_dict['Operational_Id_Ratio'] = len(operationIds) / (total_events)

    feature_dict['Rule_Names_Entropy'] = rule_names_entropy_value

    feature_dict['Avg_File_Count'] = fileCount_count / total_events

    feature_dict['File_Version_Build_Info_Weighted'] = file_version_build_info / total_events

    feature_dict['Script_Block_Ratio'] = script_blocks / total_events

    return feature_dict


def process_event(event, event_counts, all_event_times, file_paths, process_ids, parent_processes, unique_event_ids,
                  total_command_line_args, burst_event_count, process_paths, current_dir_paths, child_processes,
                  exe_folder):
    event_type = event.get('Event_System_EventID')
    event_time = event.get('Event_System_TimeCreated_@SystemTime')

    if isValidValue(event_time):
        all_event_times.append(event_time)

    event_counts[event_type] += 1

    if len(all_event_times) > 1:
        time_diff = (pd.Timestamp(all_event_times[-1]) - pd.Timestamp(all_event_times[-2])).total_seconds()
        if time_diff < 2:
            burst_event_count.add(time_diff)

    if isValidValue(event_type) and event_type not in unique_event_ids:
        unique_event_ids.add(event_type)

    process_id = event.get('ProcessId')
    if isValidValue(process_id):
        process_ids.add(process_id)

    process_path = event.get('ProcessPath')
    current_dir = event.get('CurrentDirectory')
    parent_image = event.get('ParentImage')
    for dir in suspicious_directories:
        if isValidValue(process_path) and dir in process_path:
            process_paths.add(process_path)
        if isValidValue(current_dir) and dir in current_dir:
            current_dir_paths.add(current_dir)
        if isValidValue(parent_image) and dir in parent_image:
            process_paths.add(process_path)

    parent_process_id = event.get('ParentProcessId')
    if isValidValue(parent_process_id):
        parent_processes.append(parent_process_id)
        child_processes.add(process_id)

    file_path = event.get('Image')
    if isValidValue(file_path):
        if exe_folder not in file_path:
            file_paths.add(file_path)


def calculate_statistical_features(event_counts, event_times, file_paths, process_ids, parent_processes,
                                   child_processes,
                                   unique_event_ids, file_extensions,
                                   total_command_line_args, process_paths):
    feature_dict = {}
    total_events = sum(event_counts.values()) + 1

    feature_dict['Total_Number_of_Events'] = sum(event_counts.values()) / running_time

    total_parents = len(parent_processes)
    avg_children_per_parent = len(child_processes) / (total_parents + 1)
    feature_dict['Avg_Children_Per_Parent'] = avg_children_per_parent

    feature_dict['Suspicious_Process_Path'] = len(process_paths) / total_events
    feature_dict['Unique_File_Paths_Accessed'] = (len(set(file_paths))) / (total_events + 1)

    if event_times:
        event_times = pd.to_datetime(event_times)
        event_durations = event_times.diff().total_seconds()[1:]
        event_durations = event_durations.values

        feature_dict['Total_Execution_Time'] = abs(event_times[-1] - event_times[0]).total_seconds()
        feature_dict['Average_Event_Time_Interval'] = abs(event_durations.mean()) if len(event_durations) > 0 else 0
        feature_dict['Std_Event_Time_Interval'] = abs(event_durations.std(ddof=0)) if len(event_durations) > 0 else 0

    process_counts = Counter(process_ids)
    process_count_values = np.array(list(process_counts.values()))
    if process_count_values.size > 0:
        feature_dict['Process_ID_Entropy'] = entropy(process_count_values)
    else:
        feature_dict['Process_ID_Entropy'] = 0

    event_count_values = list(event_counts.values())
    feature_dict['Mean_Event_Count'] = (pd.Series(event_count_values).mean()) / total_events
    feature_dict['Median_Event_Count'] = (pd.Series(event_count_values).median()) / total_events

    feature_dict['Event_Kurtosis'] = (kurtosis(event_count_values) + 1)

    return feature_dict


malware_log_dir = "Malware_Log_Path"
benign_log_dir = "Benign_Log_Path"
malware_feature_matrix = process_folder(malware_log_dir, is_malware=1)
benign_feature_matrix = process_folder(benign_log_dir, is_malware=0)

combined_matrix = pd.concat([malware_feature_matrix, benign_feature_matrix])
print(logons)
print(logons2)

feature_columns = [col for col in combined_matrix.columns if col not in ['folder_name', 'Is_Malware']]

combined_matrix[feature_columns] = combined_matrix[feature_columns].fillna(0)
combined_matrix.to_csv('Normal_Feature_Set.csv', index=False, float_format='%.12f')
