import pandas as pd

pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', 1000)
pd.set_option('display.max_columns', None)

df = pd.read_csv('ClassifierResults.csv')

eps, tau, alpha = 0.07, 0.2, 0.75

mask = (

)
filtered = df
output_csv = 'NewOutlierStats.csv'

filtered.to_csv(output_csv, mode='w', index=False, header=True)

df = filtered

numeric_cols = ['Avg ConfMat_TP', 'Avg ConfMat_FP', 'Avg ConfMat_FN', 'Avg ConfMat_TN', 'Prec_Ben', 'Prec_Mal', 'F1']
df[numeric_cols] = df[numeric_cols].astype(float)

stats = df.groupby('Set')[numeric_cols].agg(['mean', 'std']).round(4)

stats.columns = ['_'.join(col).strip() for col in stats.columns.values]

latex_table = stats.to_latex(
    caption="Average And Std",
    label="tab:set_statistics",
    float_format="%.4f"
)

print(latex_table)
print(stats)
