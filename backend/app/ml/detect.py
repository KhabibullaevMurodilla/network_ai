"""
Anomaly detection pipeline for network flow telemetry.

Trains PyOD detectors (Isolation Forest + ECOD) on flow-level features,
treating the problem the way a real deployment would: the model does NOT
see the Label/IsAnomaly columns during training (unsupervised), and those
are used only afterward to score detection quality -- mirroring how the
engine would work against live customer telemetry with no ground truth.
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
)
from pyod.models.iforest import IForest
from pyod.models.ecod import ECOD

FEATURES = ["Dur", "TotPkts", "SrcBytes", "DstBytes", "Rate", "Load", "sTtl"]


def load_data(path="/home/claude/ad-demo/data/synthetic_5g_flows.csv"):
    return pd.read_csv(path)


def build_feature_matrix(df):
    X = df[FEATURES].copy()
    proto_enc = LabelEncoder()
    X["ProtoEnc"] = proto_enc.fit_transform(df["Proto"])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled


def evaluate(y_true, scores, y_pred, model_name):
    return {
        "model": model_name,
        "roc_auc": roc_auc_score(y_true, scores),
        "precision": precision_score(y_true, y_pred),
        "recall": recall_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def run():
    df = load_data()
    X = build_feature_matrix(df)
    y_true = df["IsAnomaly"].values

    # contamination set to the true anomaly rate here for demo purposes;
    # in production this would be a tunable operating threshold, not known in advance
    contamination = float(y_true.mean())

    results = {}
    scored = {}

    iforest = IForest(contamination=contamination, random_state=42, n_estimators=200)
    iforest.fit(X)
    scored["IsolationForest"] = iforest.decision_scores_
    results["IsolationForest"] = evaluate(
        y_true, iforest.decision_scores_, iforest.labels_, "IsolationForest"
    )

    ecod = ECOD(contamination=contamination)
    ecod.fit(X)
    scored["ECOD"] = ecod.decision_scores_
    results["ECOD"] = evaluate(
        y_true, ecod.decision_scores_, ecod.labels_, "ECOD"
    )

    df_out = df.copy()
    for name, s in scored.items():
        df_out[f"score_{name}"] = s
    df_out.to_csv("/home/claude/ad-demo/outputs/scored_flows.csv", index=False)

    return results, df_out


if __name__ == "__main__":
    results, df_out = run()
    for name, r in results.items():
        print(f"\n=== {name} ===")
        print(f"  ROC-AUC:   {r['roc_auc']:.3f}")
        print(f"  Precision: {r['precision']:.3f}")
        print(f"  Recall:    {r['recall']:.3f}")
        print(f"  F1:        {r['f1']:.3f}")
        print(f"  Confusion matrix [[TN,FP],[FN,TP]]: {r['confusion_matrix']}")

    import json
    with open("/home/claude/ad-demo/outputs/results.json", "w") as f:
        json.dump(results, f, indent=2)
