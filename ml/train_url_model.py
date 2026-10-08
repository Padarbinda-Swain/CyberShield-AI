"""Train & compare URL classifiers; persist the best one + metrics for the admin dashboard."""
import json, pathlib, time
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from url_scanner.features import FEATURE_NAMES, extract_features

ART = pathlib.Path(__file__).parent / "artifacts"
DATA = pathlib.Path(__file__).parent / "data" / "urls.csv"
CLASSES = ["safe", "suspicious", "phishing", "malicious"]


def candidates():
    models = {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=2.0)),
        "Random Forest": RandomForestClassifier(n_estimators=250, min_samples_leaf=2, n_jobs=-1, random_state=7),
    }
    try:
        from xgboost import XGBClassifier
        models["XGBoost"] = XGBClassifier(n_estimators=250, max_depth=5, learning_rate=0.1, subsample=0.9,
                                          eval_metric="mlogloss", random_state=7, n_jobs=2)
    except Exception:
        print("xgboost not installed - skipping")
    return models


def main():
    if not DATA.exists():
        from ml.generate_url_dataset import main as gen; gen()
    df = pd.read_csv(DATA)
    X = pd.DataFrame([extract_features(u) for u in df.url])[FEATURE_NAMES]
    y = df.label.map({c: i for i, c in enumerate(CLASSES)}).values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=1)
    results, best, best_f1 = [], None, -1
    for name, model in candidates().items():
        t = time.time(); model.fit(Xtr, ytr); proba = model.predict_proba(Xte); pred = proba.argmax(1)
        m = {"model": name, "accuracy": accuracy_score(yte, pred),
             "precision": precision_score(yte, pred, average="macro"), "recall": recall_score(yte, pred, average="macro"),
             "f1": f1_score(yte, pred, average="macro"), "roc_auc": roc_auc_score(yte, proba, multi_class="ovr"),
             "confusion_matrix": confusion_matrix(yte, pred).tolist(), "train_seconds": round(time.time() - t, 2)}
        results.append({k: (round(v, 4) if isinstance(v, float) else v) for k, v in m.items()})
        print(f"{name:20s} acc={m['accuracy']:.4f} f1={m['f1']:.4f} auc={m['roc_auc']:.4f}")
        if m["f1"] > best_f1: best, best_f1, best_name = model, m["f1"], name
    ART.mkdir(exist_ok=True)
    joblib.dump({"model": best, "features": FEATURE_NAMES, "classes": CLASSES, "name": best_name}, ART / "url_model.joblib")
    importances = None
    est = best.steps[-1][1] if hasattr(best, "steps") else best
    if hasattr(est, "feature_importances_"):
        importances = dict(zip(FEATURE_NAMES, map(float, est.feature_importances_)))
    (ART / "url_metrics.json").write_text(json.dumps({"best": best_name, "classes": CLASSES, "samples": len(df),
                                                       "results": results, "feature_importance": importances}, indent=2))
    print("best:", best_name)


if __name__ == "__main__":
    main()
