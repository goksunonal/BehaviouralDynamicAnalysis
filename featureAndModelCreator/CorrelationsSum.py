from collections import defaultdict

import pandas as pd

pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', 1000)
pd.set_option('display.max_columns', None)

file_path1 = 'Aggressive_Feature_Set.csv'
file_path2 = 'Aggressive_Test_Set.csv'

data1 = pd.read_csv(file_path1)
data2 = pd.read_csv(file_path2)

assert list(data1.columns) == list(data2.columns), "Columns do not match!"

combined_data = pd.concat([data1, data2], ignore_index=True)

X = combined_data.drop(columns=['folder_name', 'Is_Malware'])

correlation_matrix = X.corr()

correlations = correlation_matrix.unstack()

sorted_correlations = correlations.sort_values(ascending=False)

strong_correlations = sorted_correlations[(sorted_correlations < 1.0) & (sorted_correlations > -1.0)]

top_positive_correlations = strong_correlations[strong_correlations > 0.9]
top_negative_correlations = strong_correlations[strong_correlations > -0.5]

print("Top Positive Correlations:")

print("\nTop Negative Correlations:")

y = combined_data['Is_Malware']

X_with_target = pd.concat([X, y], axis=1)

strong_correlations.to_csv("CorrelationResults.csv")

y = combined_data['Is_Malware']

X_with_target = pd.concat([X, y], axis=1)

correlation_with_target = X_with_target.corr()['Is_Malware'].sort_values(ascending=False)

print("Correlation between features and malware status (Is_Malware):")
print(correlation_with_target)

print(top_positive_correlations[1::2])

ea = defaultdict(int)
for e in top_positive_correlations.keys():
    ea[e[0]] += 1
    ea[e[1]] += 1

ea_sorted = dict(sorted(ea.items(), key=lambda item: item[1], reverse=True))

for a in ea_sorted.keys():
    print(f"{a} + {ea_sorted[a] / 2}")

import numpy as np

correlation_matrix = X.corr()

np.fill_diagonal(correlation_matrix.values, np.nan)

overall_avg_correlation = top_positive_correlations.abs().mean().mean()
overall_avg1_correlation = correlation_with_target.mean().mean()

avgCorr1 = 0
count = 0
for corr in top_positive_correlations:
    count += 1
    avgCorr1 += abs(corr)

print(f"Overall Average Correlation: {avgCorr1 / count}")

avgCorr1 = 0
count = 0
for corr in correlation_with_target:
    count += 1
    avgCorr1 += corr

print(f"Overall Malware Average Correlation: {avgCorr1 / count}")

count = 0
for a in ea_sorted.keys():
    count += ea_sorted[a]

print(f"summed: {count / 2}")

