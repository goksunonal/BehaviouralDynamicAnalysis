import numpy as np
import pandas as pd
from scipy.stats import zscore, ttest_rel
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, roc_auc_score, classification_report,
    confusion_matrix, f1_score, precision_score
)
from sklearn.model_selection import StratifiedKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import MinMaxScaler, RobustScaler
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.base import clone

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.max_colwidth', 1000)



def evaluate_on_external_test(model, scaler, X_ext, y_ext):
    X_ext_scaled = scaler.transform(X_ext) if scaler else X_ext.values
    y_pred = model.predict(X_ext_scaled)
    return accuracy_score(y_ext, y_pred)


def remove_outliers_iqr(df, k=1.5):
    num = df.select_dtypes(include=[np.number])
    iqr = num.quantile(0.75) - num.quantile(0.25)
    mask = ~((num < (num.quantile(0.25) - k * iqr)) |
             (num > (num.quantile(0.75) + k * iqr))).any(axis=1)
    return df.loc[mask]


def remove_outliers_zscore(df, thresh=3.0):
    num = df.select_dtypes(include=[np.number])
    mask = (np.abs(zscore(num, nan_policy='omit')) < thresh).all(axis=1)
    return df.loc[mask]


def remove_outliers_isoforest(df, contamination=0.01, random_state=42):
    mask = IsolationForest(
        contamination=contamination, random_state=random_state
    ).fit_predict(df.select_dtypes(include=[np.number])) == 1
    return df.loc[mask]


outlier_methods = {
    'none': lambda df: df,
    'iqr': remove_outliers_iqr,
    'zscore': remove_outliers_zscore,
    'isoforest': remove_outliers_isoforest
}

feature_sets = {
    'Aggressive_Feature_Set.csv',
    'Normal_Feature_Set.csv',
    'Raw_Feature_Set.csv'
}

scalers = {
    'MinMaxScaler': MinMaxScaler(),
    'RobustScaler': RobustScaler()
}

results = pd.DataFrame()
baseline_acc_dict = {}


for feat_set in feature_sets:
    df_all = pd.read_csv(feat_set).replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_full, y_full = df_all.drop(columns=['folder_name', 'Is_Malware']), df_all['Is_Malware']

    classifiers = {
        'RandomForest': RandomForestClassifier(
            n_estimators=200, max_depth=10, min_samples_split=10,
            min_samples_leaf=5, max_features='sqrt',
            class_weight='balanced', random_state=42),
        'LogisticRegression': LogisticRegression(max_iter=1_000_000, class_weight='balanced', random_state=42),
        'SVC': SVC(probability=True, class_weight='balanced', random_state=42),
        'KNeighbors': KNeighborsClassifier(),
        'GradientBoosting': GradientBoostingClassifier(random_state=42),
        'MLPClassifier': MLPClassifier(max_iter=1_000_000, random_state=42),
        'XGBoost': XGBClassifier(
            n_estimators=200, max_depth=5, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8, reg_alpha=1,
            reg_lambda=1, use_label_encoder=False, eval_metric="logloss",
            random_state=42)
    }


    ext_file = feat_set.replace('Feature', 'Test')
    X_ext = pd.read_csv(ext_file).drop(columns=['folder_name', 'Is_Malware'])
    y_ext = pd.read_csv(ext_file)['Is_Malware']

    kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for scaler_name, scaler in scalers.items():
        for clf_name, clf in classifiers.items():
            for out_name, out_func in outlier_methods.items():
                df_clean = out_func(pd.concat([X_full, y_full], axis=1))
                X, y = df_clean.drop(columns=['Is_Malware']), df_clean['Is_Malware']

                fold_acc, fold_auc, fold_ext = [], [], []  
                f1_list, prec0_list, prec1_list = [], [], []
                cm_sum = np.zeros((2, 2), dtype=int)

                for train_idx, test_idx in kf.split(X, y):
                    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
                    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

                    if scaler:
                        scaler.fit(X_train)
                        X_train, X_test_sc = scaler.transform(X_train), scaler.transform(X_test)
                    else:
                        X_train, X_test_sc = X_train.values, X_test.values

                    model = clone(clf).fit(X_train, y_train)

                    y_test_pred = model.predict(X_test_sc)
                    y_test_proba = (
                        model.predict_proba(X_test_sc)[:, 1]
                        if hasattr(model, 'predict_proba') else None
                    )

                    fold_ext.append(evaluate_on_external_test(model, scaler, X_ext, y_ext))
                    fold_acc.append(accuracy_score(y_test, y_test_pred))
                    fold_auc.append(
                        roc_auc_score(y_test, y_test_proba) if y_test_proba is not None else 0.0
                    )
                    print(scaler_name, clf_name)
                    print(f"Classification Report:\n{classification_report(y_test, y_test_pred)}")
                    cm_sum += confusion_matrix(y_test, y_test_pred, labels=[0, 1])
                    f1_list.append(f1_score(y_test, y_test_pred))
                    prec0_list.append(precision_score(y_test, y_test_pred, pos_label=0))
                    prec1_list.append(precision_score(y_test, y_test_pred, pos_label=1))


                mean_acc, std_acc = np.mean(fold_acc), np.std(fold_acc, ddof=1)
                mean_auc, std_auc = np.mean(fold_auc), np.std(fold_auc, ddof=1)
                mean_ext, std_ext = np.mean(fold_ext), np.std(fold_ext, ddof=1)

                key = (out_name, feat_set, scaler_name)
                if clf_name == 'RandomForest':
                    baseline_acc_dict[key] = fold_acc.copy()
                    p_val = np.nan
                else:
                    base = baseline_acc_dict.get(key, [])
                    p_val = ttest_rel(base, fold_acc).pvalue if base else np.nan


                ext_acc = evaluate_on_external_test(model, scaler, X_ext, y_ext)

                results = results._append({
                    'Outlier': out_name,
                    'Set': feat_set,
                    'Scaler': scaler_name,
                    'Classifier': clf_name,
                    'Acc (mean±sd)': f'{mean_acc:.3f} ± {std_acc:.3f}',
                    'AUC (mean±sd)': f'{mean_auc:.3f} ± {std_auc:.3f}',
                    'External Test Acc': f'{ext_acc:.5f}',
                    'Fold External Test Acc': f'{mean_ext:.3f} ± {std_ext:.3f}',
                    'p-val vs RF': '' if np.isnan(p_val) else f'{p_val:.4f}',
                    'F1 (mean)': f'{np.mean(f1_list):.3f}',
                }, ignore_index=True)


results.sort_values(['Set', 'Scaler', 'Outlier', 'Classifier'], inplace=True)
results.to_csv('ClassifierResultsWithStdMean.csv', index=False)
print(results.head(20))
