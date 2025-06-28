import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', 1000)
pd.set_option('display.max_columns', None)


def iqr_mask(frame):
    Q1 = frame[numeric_cols].quantile(0.25)
    Q3 = frame[numeric_cols].quantile(0.75)
    IQR = Q3 - Q1
    lower, upper = Q1 - 1.5 * IQR, Q3 + 1.5 * IQR
    return ~(((frame[numeric_cols] >= lower) & (frame[numeric_cols] <= upper)).all(axis=1))


def zscore_mask(frame, thr=3):
    z = (frame[numeric_cols] - frame[numeric_cols].mean()) / frame[numeric_cols].std(ddof=0)
    return (np.abs(z) > thr).any(axis=1)


def iso_mask(frame, contamination=0.1, seed=42):
    iso = IsolationForest(contamination=contamination, random_state=seed)
    return iso.fit_predict(frame[numeric_cols]) == -1


files = {
    'Aggressive': 'Aggressive_Input_Set',
    'Raw': 'Raw_Input_Set',
    'Normal': 'Normal_Input_Set'
}
results = pd.DataFrame(
    columns=["Set", "Rule", "Rows Removed", "% Removed", "Median ‖ΔMean‖ / Mean", "Malware % After"])

for file, file_path in files.items():
    df = pd.read_csv(file_path)

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    numeric_cols.remove('Is_Malware')

    masks = {
        "IQR": iqr_mask(df),
        "Z‑Score (|z|>3)": zscore_mask(df),
        "Isolation Forest": iso_mask(df)
    }

    summary = []
    total_rows = len(df)
    orig_malware_pct = df['Is_Malware'].mean() * 100

    for name, mask in masks.items():
        kept = df.loc[~mask]
        removed = mask.sum()
        summary.append({
            "Set": file,
            "Rule": name,
            "Rows Removed": removed,
            "% Removed": round(removed / total_rows * 100, 2),
            "Median ‖ΔMean‖ / Mean": round(((kept[numeric_cols].mean() - df[numeric_cols].mean()).abs() / df[
                numeric_cols].mean().replace(0, np.nan)).median(), 3),
            "Malware % After": 36.8 - round(kept['Is_Malware'].mean() * 100, 2),
        })

    results = results._append(summary)

print(results)
output_csv = 'OutlierStats.csv'

results.to_csv(output_csv, mode='w', index=False, header=True)
