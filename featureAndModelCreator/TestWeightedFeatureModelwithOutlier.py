import numpy as np
import pandas as pd
from scipy.stats import zscore
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report, confusion_matrix, f1_score, \
    precision_score
from sklearn.model_selection import StratifiedKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import MinMaxScaler, RobustScaler
from sklearn.svm import SVC
from xgboost import XGBClassifier

pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', 1000)
pd.set_option('display.max_columns', None)


def evaluate_on_external_test(model, model_type, scaler, X_external_test, y_external_test):
    if scaler is not None:
        X_external_test_scaled = scaler.transform(X_external_test)
    else:
        X_external_test_scaled = X_external_test.values

    if model_type == 'ml':
        y_pred_external = model.predict(X_external_test_scaled)
    else:
        y_pred_external_proba = model.predict(X_external_test_scaled).ravel()
        y_pred_external = (y_pred_external_proba >= 0.5).astype(int)

    external_test_accuracy = accuracy_score(y_external_test, y_pred_external)
    return external_test_accuracy


def remove_outliers_iqr(df, k=1.5):
    num = df.select_dtypes(include=[np.number])
    Q1 = num.quantile(0.25)
    Q3 = num.quantile(0.75)
    IQR = Q3 - Q1
    lower = Q1 - k * IQR
    upper = Q3 + k * IQR
    mask = ~((num < lower) | (num > upper)).any(axis=1)
    return df.loc[mask]


def remove_outliers_zscore(df, thresh=3.0):
    num = df.select_dtypes(include=[np.number])
    z = np.abs(zscore(num, nan_policy='omit'))
    mask = (z < thresh).all(axis=1)
    return df.loc[mask]


def remove_outliers_isoforest(df, contamination=0.01, random_state=42):
    num = df.select_dtypes(include=[np.number])
    iso = IsolationForest(contamination=contamination, random_state=random_state)
    mask = iso.fit_predict(num) == 1
    return df.loc[mask]


outlier_methods = {
    'none': lambda df: df,
    'iqr': remove_outliers_iqr,
    'zscore': remove_outliers_zscore,
    'isoforest': remove_outliers_isoforest
}

sets = {
    'Aggressive_Feature_Set.csv',
    'Normal_Feature_Set.csv',
    'Raw_Feature_Set.csv',
}
scalers = {
    'MinMaxScaler': MinMaxScaler(),
    'RobustScaler': RobustScaler()
}

results = pd.DataFrame(
    columns=['Outlier', 'Set', 'Scaler', 'Classifier', 'Avg Train Accuracy', 'Avg Validation Accuracy', 'Avg ROC AUC',
             'Avg Full Overfitting', 'Avg ConfMat_TN', 'Avg ConfMat_FP', 'Avg ConfMat_FN', 'Avg ConfMat_TP', 'Prec_Ben',
             'Prec_Mal',
             'F1'])

for set in sets:
    feature_matrix = pd.read_csv(set)

    feature_matrix.replace([np.inf, -np.inf], np.nan, inplace=True)
    feature_matrix.fillna(0.0, inplace=True)

    X_full = feature_matrix.drop(columns=['folder_name', 'Is_Malware'])
    y_full = feature_matrix['Is_Malware']

    classifiers = {
        'RandomForest': RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=10,
            min_samples_leaf=5,
            max_features='sqrt',
            class_weight='balanced',
            random_state=42
        ),
        'LogisticRegression': LogisticRegression(max_iter=1000000, class_weight='balanced', random_state=42),
        'SVC': SVC(probability=True, class_weight='balanced', random_state=42),
        'KNeighbors': KNeighborsClassifier(),
        'GradientBoosting': GradientBoostingClassifier(random_state=42),
        'MLPClassifier': MLPClassifier(max_iter=1000000, random_state=42),
        'XGBoost': XGBClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=1,
            reg_lambda=1,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42
        )
    }

    kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for scaler_name, scaler in scalers.items():
        for clf_name, clf in classifiers.items():
            print(f"Processing {scaler_name} with {clf_name}...")

            if set == 'Aggressive_Feature_Set.csv':
                external_test_set = pd.read_csv('Aggressive_Test_Set.csv')
            elif set == 'Normal_Feature_Set.csv':
                external_test_set = pd.read_csv('Normal_Test_Set.csv')
            else:
                external_test_set = pd.read_csv('Raw_Test_Set.csv')

            X_external_test = external_test_set.drop(columns=['folder_name', 'Is_Malware'])
            y_external_test = external_test_set['Is_Malware']

            for out_name, out_func in outlier_methods.items():
                df = pd.concat([X_full, y_full], axis=1)
                df_clean = out_func(df)
                X = df_clean.drop(columns=['Is_Malware'])
                y = df_clean['Is_Malware']

                train_acc_total = 0
                test_acc_total = []
                roc_auc_total = 0
                overfitting_total = 0
                full_overfitting = 0
                fold_count = 0
                external_test_accuracy_local = []
                f1_total = []
                prec_ben_total = []
                prec_mal_total = []
                cm_sum = np.zeros((2, 2), dtype=int)
                for train_index, test_index in kf.split(X, y):
                    X_train_full, X_test = X.iloc[train_index], X.iloc[test_index]
                    y_train_full, y_test = y.iloc[train_index], y.iloc[test_index]

                    if scaler is not None:
                        scaler.fit(X_train_full)
                        X_train = scaler.transform(X_train_full)
                        X_test_scaled = scaler.transform(X_test)
                    else:
                        X_train = X_train_full.values
                        X_test_scaled = X_test.values

                    from sklearn.base import clone

                    model = clone(clf)

                    model.fit(X_train, y_train_full)

                    y_train_pred = model.predict(X_train)
                    train_accuracy = accuracy_score(y_train_full, y_train_pred)

                    y_test_pred = model.predict(X_test_scaled)
                    y_test_proba = model.predict_proba(X_test_scaled)[:, 1] if hasattr(model, 'predict_proba') else None

                    test_accuracy = accuracy_score(y_test, y_test_pred)
                    roc_auc = roc_auc_score(y_test, y_test_proba) if y_test_proba is not None else 0.0
                    cm_sum += confusion_matrix(y_test, y_test_pred, labels=[0, 1])
                    f1_total.append(f1_score(y_test, y_test_pred))
                    prec_ben_total.append(precision_score(y_test, y_test_pred, pos_label=0))
                    prec_mal_total.append(precision_score(y_test, y_test_pred, pos_label=1))

                    overfitting_score = train_accuracy - test_accuracy

                    train_acc_total += train_accuracy
                    test_acc_total.append(test_accuracy)
                    roc_auc_total += roc_auc
                    overfitting_total += overfitting_score
                    local_value = evaluate_on_external_test(model, 'ml', scaler, X_external_test,
                                                            y_external_test)

                    external_test_accuracy_local.append(local_value)

                    full_overfitting += abs(
                        overfitting_score + (train_accuracy - np.min(external_test_accuracy_local)) + (
                                train_accuracy - local_value))
                    print(f"Train Accuracy: {train_accuracy}")
                    print(f"Test Accuracy: {test_accuracy}")
                    print(f"ROC AUC Score: {roc_auc}")
                    print(f"Classification Report:\n{classification_report(y_test, y_test_pred)}")
                    print("-" * 60)
                    fold_count += 1

                avg_train_acc = train_acc_total / fold_count
                avg_test_acc = np.mean(test_acc_total)
                avg_roc_auc = roc_auc_total / fold_count
                avg_overfitting = overfitting_total / fold_count
                avg_full_overfitting = full_overfitting / fold_count
                f1_avg = np.mean(f1_total)
                prec_ben_avg = np.mean(prec_ben_total)
                prec_mal_avg = np.mean(prec_mal_total)
                cm_avg = cm_sum
                print("Average Confusion Matrix (k={}):\n{}".format(fold_count, cm_avg))
                print("Average prec Matrix (k={}):\n{}".format(fold_count, prec_mal_avg))
                print("Average f1 Matrix (k={}):\n{}".format(fold_count, f1_avg))

                results = results._append({
                    'Outlier': out_name,
                    'Set': set,
                    'Scaler': scaler_name,
                    'Classifier': clf_name,
                    'Avg Train Accuracy': avg_train_acc,
                    'Avg Validation Accuracy': avg_test_acc,
                    'Avg ROC AUC': avg_roc_auc,
                    'Avg Full Overfitting': avg_full_overfitting,
                    'Lowest Accuracy': np.min(test_acc_total),
                    'External Test Accuracy': np.mean(external_test_accuracy_local),
                    'Avg ConfMat_TP': cm_avg[0, 0],
                    'Avg ConfMat_FP': cm_avg[0, 1],
                    'Avg ConfMat_FN': cm_avg[1, 0],
                    'Avg ConfMat_TN': cm_avg[1, 1],
                    'Prec_Ben': prec_ben_avg,
                    'Prec_Mal': prec_mal_avg,
                    'F1': f1_avg,

                }, ignore_index=True)

results.reset_index(drop=True, inplace=True)

print("\nFinal Results sorted by Average Overfitting Metric:")
print(results.sort_values(by='Avg Full Overfitting', ascending=True))

output_csv = 'ClassifierResults.csv'

results.to_csv(output_csv, mode='w', index=False, header=True)
