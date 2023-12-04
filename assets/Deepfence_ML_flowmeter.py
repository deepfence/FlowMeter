# Import libraries
from __future__ import division

import pandas as pd
import matplotlib.pyplot as plt  # plotting
import numpy as np  # linear algebra
import math

from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC

from sklearn.pipeline import make_pipeline

from sklearn.preprocessing import StandardScaler, MinMaxScaler

from sklearn.model_selection import (
    train_test_split,
    GridSearchCV,
    cross_val_score,
    RepeatedStratifiedKFold,
    StratifiedKFold,
)

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    roc_curve,
    roc_auc_score,
    auc,
    precision_score,
    recall_score,
    precision_recall_curve,
    plot_confusion_matrix,
    f1_score,
)
from sklearn.metrics import plot_confusion_matrix

from collections import Counter
from sklearn.datasets import make_classification
import copy
import warnings


# # Data

# ### File path
folder = "../pkg/flowOutput/"
fname_benign = "2017-05-02_kali-normal22_flow_stats.csv"
fname_malicious = "webgoat_flow_stats.csv"

# ### Malicious: Webgoat
# Malicious flows
pd_malicious = pd.read_csv(folder + fname_malicious)
pd_malicious.drop(pd_malicious.tail(1).index, inplace=True)
pd_malicious["Type"] = "Malicious"


# ### Benign
# Benign flows
pd_benign = pd.read_csv(folder + fname_benign)
# pd_benign.drop(pd_webgoat.tail(1).index, inplace=True)
pd_benign["Type"] = "Benign"

print(pd_benign.shape)


# ### Combined dataframe - Benign + malicious
## Combine malicous and benign dataframes.
pd_comb = pd.concat([pd_malicious, pd_benign])

## Random shuffle of rows
pd_comb = pd_comb.sample(frac=1)

pd_comb.shape

# ### Added throughput columns.
## Add throughput columns.
colsPerTime = [
    "flowLength",
    "fwdFlowLength",
    "bwdFlowLength",
    "packetSizeTotal",
    "fwdPacketSizeTotal",
    "bwdPacketSizeTotal",
]

for feature in colsPerTime:
    pd_comb[feature + "PerTime"] = pd_comb[feature] / pd_comb["flowDuration"]
    print(feature + "PerTime")

# ## Features
# Feature columns.
feature_cols = [
    "flowDuration",
    "flowLength",
    "fwdFlowLength",
    "bwdFlowLength",
    "packetSizeTotal",
    "packetSizeMean",
    "packetSizeStd",
    "packetSizeMin",
    "packetSizeMax",
    "fwdPacketSizeTotal",
    "bwdPacketSizeTotal",
    "fwdPacketSizeMean",
    "bwdPacketSizeMean",
    "fwdPacketSizeStd",
    "bwdPacketSizeStd",
    "fwdPacketSizeMin",
    "bwdPacketSizeMin",
    "fwdPacketSizeMax",
    "bwdPacketSizeMax",
    "IATMean",
    "IATStd",
    "IATMin",
    "IATMax",
    "fwdIATTotal",
    "bwdIATTotal",
    "fwdIATMean",
    "bwdIATMean",
    "fwdIATStd",
    "bwdIATStd",
    "fwdIATMin",
    "bwdIATMin",
    "fwdIATMax",
    "bwdIATMax",
    "flowLengthPerTime",
    "fwdFlowLengthPerTime",
    "bwdFlowLengthPerTime",
    "packetSizeTotalPerTime",
    "fwdPacketSizeTotalPerTime",
    "bwdPacketSizeTotalPerTime",
    "Type",
]


# ### Dataframe with chosen features
## Select feature columns in datasets.
pd_comb_features = pd_comb[feature_cols]


# # Machine learning - feature importance


# ## Clean dataset
# Remove spurious entries from dataset.
def clean_dataset(df):
    assert isinstance(df, pd.DataFrame), "df needs to be a pd.DataFrame"
    df.dropna(inplace=True)

    df_X = df.iloc[:, :-1]
    df_Y = df.iloc[:, -1]

    indices_to_keep = ~df_X.isin([np.nan, np.inf, -np.inf]).any(1)
    return df_X[indices_to_keep].astype(np.float64).values, df_Y[indices_to_keep].values


# ### Get feature and class arrays (X and y.)
# Get feature and class arrays (X and y.)
pd_comb_features_cp = pd_comb_features.copy(deep=True)

X, y = clean_dataset(pd_comb_features_cp)


# ## Train test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)


# ## Scale data
scaler = StandardScaler()  # MinMaxScaler
X_train_scale = scaler.fit_transform(X_train)
X_test_scale = scaler.transform(X_test)


# ## Weighted Logistic Regression


# ### Hyperparameter grid search.
# Class weights.
w = [
    {0: 0.10, 1: 99.90},
    {0: 0.25, 1: 99.75},
    {0: 0.50, 1: 99.50},
    {0: 0.75, 1: 99.25},
    {0: 1.00, 1: 99.00},
    {
        0: 100 * np.sum(y == "Malicious") / (np.sum(y == "Benign") + np.sum(y == "Malicious")),
        1: 100 * np.sum(y == "Benign") / (np.sum(y == "Benign") + np.sum(y == "Malicious")),
    },
]

# Inverse of regularization strength.
crange = np.arange(0.1, 1.0, 0.2)


# Hyperparameter grid.
hyperparam_grid = {
    "class_weight": w,
    "penalty": ["l1", "l2"],
    "C": crange,
    "fit_intercept": [True, False],
}


# ### Prepare samples.
# String to int for classes
y_train2 = np.copy(y_train)
y_train2[np.where(y_train == "Benign")[0]] = 0
y_train2[np.where(y_train == "Malicious")[0]] = 1


# ### Model fitting.
# logistic model classifier.
lg = LogisticRegression(random_state=13)

# define evaluation procedure
grid = GridSearchCV(lg, hyperparam_grid, scoring="roc_auc", cv=10, n_jobs=-1, refit=True)
grid.fit(X_train_scale, y_train2.astype("int32"))

print(f"Best score: {grid.best_score_} with param: {grid.best_params_}")


# ### Test perfomance.
y_pred_wt = grid.predict(X_test_scale)

y_test2 = np.copy(y_test)
y_test2[np.where(y_test == "Benign")[0]] = 0
y_test2[np.where(y_test == "Malicious")[0]] = 1


# performance
conf_mat = confusion_matrix(y_test2.astype("int32"), y_pred_wt)

print(f"Accuracy Score: {accuracy_score(y_test2.astype('int32'),y_pred_wt)}")
print(f"Confusion Matrix: \n{confusion_matrix(y_test2.astype('int32'), y_pred_wt)}")
print(f"Area Under Curve: {roc_auc_score(y_test2.astype('int32'), y_pred_wt)}")
print(
    f"Recall score (Pct of true malicious detected): {100*recall_score(y_test2.astype('int32'), y_pred_wt)}"
)
print(f"Data reduction: { np.round( 100.0 * conf_mat.T[1].sum() / conf_mat.sum() , 2 )} percent")

print(
    f"Pct malicious in data sent to console: { np.round( 100.0 * conf_mat.T[1][1] / conf_mat.T[1].sum() , 2 )} percent"
)

print("F1 score: ", f1_score(y_test2.astype("int32"), y_pred_wt, average="weighted"))


# ### Best fit parameters.
# define model
best_fit_model = LogisticRegression(
    class_weight=grid.best_params_["class_weight"],
    penalty=grid.best_params_["penalty"],
    C=grid.best_params_["C"],
    fit_intercept=grid.best_params_["fit_intercept"],
    random_state=13,
    max_iter=5,
)

# fit it
best_fit_model.fit(X_train_scale, y_train2.astype("int32"))


# ### Save parameters.
np.savetxt("../pkg/ml/parameters/mean.txt", scaler.mean_, delimiter=",")
np.savetxt("../pkg/ml/parameters/std.txt", scaler.scale_, delimiter=",")
np.savetxt("../pkg/ml/parameters/weights.txt", best_fit_model.coef_[0], delimiter=",")
np.savetxt("../pkg/ml/parameters/intercept.txt", best_fit_model.intercept_, delimiter=",")


# ### Feature importance scores
important_features = pd_comb_features_cp.iloc[:, :-1].columns.values[
    np.argsort(-1 * np.abs(best_fit_model.coef_[0]))
]


print(important_features)

