"""
train_unidirectional_model.py
=============================
Trains a multiclass XGBoost classifier exclusively on Unidirectional (Forward-only)
network flow features.

Key Principles:
- Eliminates all 12+ backward features (Bwd Packet Length, Bwd IAT, Bwd Header Length,
  Bwd Packets/s, Init_Win_bytes_backward) that do not exist in unidirectional traffic
  (Data Diodes, passive optical taps, single-direction capture).
- Trains on 40 forward features defined in feature_columns_unidirectional.json.
- Outputs `multiclass_xgboost_unidirectional.joblib` and `label_encoder_unidirectional.joblib`.
"""

import json
import os
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import xgboost as xgb

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(SCRIPT_DIR, "large_simulation_log.csv")
FEATURE_FILE = os.path.join(SCRIPT_DIR, "feature_columns_unidirectional.json")
OUTPUT_MODEL = os.path.join(SCRIPT_DIR, "multiclass_xgboost_unidirectional.joblib")
OUTPUT_ENCODER = os.path.join(SCRIPT_DIR, "label_encoder_unidirectional.joblib")
OUTPUT_METRICS = os.path.join(SCRIPT_DIR, "unidirectional_model_metrics.json")


def load_and_preprocess_data():
    print(f"[*] Loading feature definitions from {FEATURE_FILE}...")
    with open(FEATURE_FILE, "r") as f:
        feature_cols = json.load(f)

    print(f"[*] Loading dataset from {DATA_FILE}...")
    # Read CSV (first 50,000 to 100,000 rows for high quality training)
    df = pd.read_csv(DATA_FILE)
    df.columns = df.columns.str.strip()

    # Ensure all required features are present
    missing_cols = [c for c in feature_cols if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns in dataset: {missing_cols}")

    if "Label" not in df.columns:
        raise ValueError("Missing 'Label' column in dataset!")

    print(f"[*] Total dataset rows: {len(df):,}")
    print(f"[*] Unique classes: {df['Label'].value_counts().to_dict()}")

    X = df[feature_cols].copy()
    y = df["Label"].copy()

    # Handle Infs / NaNs
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0.0)

    # Encode labels
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    return X, y_encoded, encoder, feature_cols


def train_unidirectional_model():
    start_time = time.time()
    X, y, encoder, feature_cols = load_and_preprocess_data()

    print(f"[*] Stratified train/test split (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[*] Training XGBoost Classifier on 40 Unidirectional Features...")
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        tree_method="hist"
    )

    model.fit(X_train, y_train)

    print("[*] Evaluating model on unseen unidirectional test set...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred, target_names=encoder.classes_, output_dict=True
    )

    print(f"[+] Accuracy: {acc * 100:.2f}%")
    print("\n" + classification_report(y_test, y_pred, target_names=encoder.classes_))

    # Feature Importance
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": feature_cols[i], "importance": float(importances[i])}
        for i in sorted_idx[:15]
    ]

    print("[*] Top 10 Most Discriminative Unidirectional Features:")
    for rank, item in enumerate(top_features[:10], 1):
        print(f"  {rank:2d}. {item['feature']}: {item['importance']:.4f}")

    # Save artifacts
    print(f"[*] Saving model to {OUTPUT_MODEL}...")
    joblib.dump(model, OUTPUT_MODEL)

    print(f"[*] Saving label encoder to {OUTPUT_ENCODER}...")
    joblib.dump(encoder, OUTPUT_ENCODER)

    metrics_payload = {
        "model": "XGBClassifier (Unidirectional)",
        "features_count": len(feature_cols),
        "accuracy": float(acc),
        "classes": list(encoder.classes_),
        "top_features": top_features,
        "classification_report": report,
        "training_duration_seconds": round(time.time() - start_time, 2)
    }

    with open(OUTPUT_METRICS, "w") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"[+] Metrics saved to {OUTPUT_METRICS}")
    print("[+] Model training complete!")


if __name__ == "__main__":
    train_unidirectional_model()
