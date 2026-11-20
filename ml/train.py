"""
Model training and evaluation pipeline for AI Phishing URL Detection.
Trains and compares:
1. Random Forest (Primary model)
2. Decision Tree (Comparative)
3. Logistic Regression (Comparative)

Saves the trained model and comprehensive academic evaluation metrics.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    roc_curve
)

from .features import extract_features, FEATURE_NAMES
from .dataset import load_dataset
from .explainer import explain_url

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "model_metrics.json")


def build_dataset_dataframe() -> Tuple[pd.DataFrame, pd.Series]:
    """Extracts features for all URLs and creates a pandas DataFrame."""
    urls, labels = load_dataset()
    feature_rows = []
    for u in urls:
        feature_rows.append(extract_features(u))

    X = pd.DataFrame(feature_rows)
    y = pd.Series(labels, name="label")
    return X, y


def train_and_evaluate() -> Dict[str, Any]:
    """Trains the models, computes metrics, and persists artifacts."""
    print("Extracting features from curated dataset...")
    X, y = build_dataset_dataframe()

    # Stratified Train/Test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=12, random_state=42
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=8, random_state=42
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=42
        )
    }

    metrics_comparison = {}
    best_model = None

    for name, clf in models.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        
        # Probabilities for ROC-AUC
        if hasattr(clf, "predict_proba"):
            y_proba = clf.predict_proba(X_test)[:, 1]
        else:
            y_proba = clf.decision_function(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        roc_auc = float(roc_auc_score(y_test, y_proba))
        cm = confusion_matrix(y_test, y_pred).tolist()

        # Compute ROC Curve points for visualization
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        roc_curve_points = [
            {"fpr": round(float(f), 4), "tpr": round(float(t), 4)}
            for f, t in zip(fpr, tpr)
        ]

        metrics_comparison[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "confusion_matrix": cm,
            "roc_curve": roc_curve_points
        }

        if name == "Random Forest":
            best_model = clf

    # Extract Feature Importances from Random Forest
    rf_importances = best_model.feature_importances_
    importance_list = [
        {"feature": name, "importance": round(float(imp), 4)}
        for name, imp in zip(FEATURE_NAMES, rf_importances)
    ]
    importance_list.sort(key=lambda x: x["importance"], reverse=True)

    metrics_payload = {
        "dataset_summary": {
            "total_samples": len(X),
            "training_samples": len(X_train),
            "testing_samples": len(X_test),
            "feature_count": len(FEATURE_NAMES)
        },
        "model_comparison": metrics_comparison,
        "feature_importances": importance_list,
        "feature_names": FEATURE_NAMES
    }

    # Save Model Artifacts
    joblib.dump(best_model, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"Random Forest model saved to: {MODEL_PATH}")
    print(f"Evaluation metrics saved to: {METRICS_PATH}")
    return metrics_payload


# Cached model instance
_CACHED_MODEL = None


def get_model():
    """Loads and caches the trained Random Forest model."""
    global _CACHED_MODEL
    if _CACHED_MODEL is None:
        if not os.path.exists(MODEL_PATH):
            train_and_evaluate()
        _CACHED_MODEL = joblib.load(MODEL_PATH)
    return _CACHED_MODEL


def predict_url(raw_url: str) -> Dict[str, Any]:
    """
    Classifies a single URL using the trained model and returns full XAI report.
    """
    model = get_model()
    features = extract_features(raw_url)
    
    # Create DataFrame with exact column names
    X = pd.DataFrame([features])
    
    # Predict probability for class 1 (phishing)
    prob_phishing = float(model.predict_proba(X)[0][1])

    # Generate Explainable AI breakdown
    explanation = explain_url(raw_url, features, prob_phishing)
    explanation["url"] = raw_url
    explanation["features"] = features
    return explanation


if __name__ == "__main__":
    train_and_evaluate()
