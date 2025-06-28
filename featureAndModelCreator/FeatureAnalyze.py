import csv


def read_feature_counts(csv_file):
    feature_counts = {}
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            feature = row['Feature']
            count = int(row['Count'])
            feature_type = row['Type']
            feature_counts[feature] = {'Count': count, 'Type': feature_type}
    return feature_counts


def write_filtered_features_to_csv(features, output_file):
    sorted_dict = dict(sorted(features.items(), key=lambda item: item[1], reverse=True))

    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Feature', 'Count'])
        for feature, count in sorted_dict.items():
            writer.writerow([feature, count])


def filter_features(feature_counts, threshold=100):
    filtered_features = {'bigger_than_100': {}, 'others': {}, 'excluded': {}}
    for feature, details in feature_counts.items():
        count = details['Count']
        feature_type = details['Type']
        if '@xmlns' in feature or 'Id' in feature or 'ID' in feature or 'Time' in feature:
            filtered_features['excluded'][feature] = count
        elif count > threshold and feature_type == 'Text':
            filtered_features['bigger_than_100'][feature] = count
        else:
            filtered_features['others'][feature] = count
    return filtered_features

def filter_features_all(feature_counts, threshold=100):
    filtered_features = {'bigger_than_100': {}, 'others': {}, 'excluded': {}}
    for feature, details in feature_counts.items():
        count = details['Count']
        filtered_features['others'][feature] = count
    return filtered_features

category_name = 'Aggresive'

csv_file = category_name + '-features.csv'

output_csv_file_bigger_than_100 = category_name + '-filtered_features_bigger_than_100.csv'
output_csv_file_others = category_name + '-filtered_features_others.csv'
output_csv_file_excluded = category_name + '-filtered_features_excluded.csv'
feature_counts = read_feature_counts(csv_file)
filtered_features = filter_features_all(feature_counts)

write_filtered_features_to_csv(filtered_features['bigger_than_100'], output_csv_file_bigger_than_100)
write_filtered_features_to_csv(filtered_features['others'], output_csv_file_others)
write_filtered_features_to_csv(filtered_features['excluded'], output_csv_file_excluded)
