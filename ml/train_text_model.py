"""Train TF-IDF text classifiers (LogReg / Naive Bayes / Random Forest) for social-engineering detection.
A BERT fine-tune is documented in docs/ADVANCED_BERT.md as an optional upgrade."""
import json, pathlib, time
import joblib, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

ART = pathlib.Path(__file__).parent / "artifacts"
DATA = pathlib.Path(__file__).parent / "data" / "messages.csv"


def tfidf():
    return TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True, max_features=20000)


def main():
    if not DATA.exists():
        from ml.generate_text_dataset import main as gen; gen()
    df = pd.read_csv(DATA)
    classes = sorted(df.label.unique())
    Xtr, Xte, ytr, yte = train_test_split(df.text, df.label, test_size=0.2, stratify=df.label, random_state=3)
    models = {
        "TF-IDF + Logistic Regression": make_pipeline(tfidf(), LogisticRegression(max_iter=3000, C=8)),
        "TF-IDF + Naive Bayes": make_pipeline(tfidf(), MultinomialNB(alpha=0.2)),
        "TF-IDF + Random Forest": make_pipeline(tfidf(), RandomForestClassifier(n_estimators=250, n_jobs=-1, random_state=3)),
    }
    results, best, best_f1 = [], None, -1
    for name, m in models.items():
        t = time.time(); m.fit(Xtr, ytr); proba = m.predict_proba(Xte); pred = m.classes_[proba.argmax(1)]
        r = {"model": name, "accuracy": accuracy_score(yte, pred), "precision": precision_score(yte, pred, average="macro", zero_division=0),
             "recall": recall_score(yte, pred, average="macro"), "f1": f1_score(yte, pred, average="macro"),
             "roc_auc": roc_auc_score(yte, proba, multi_class="ovr", labels=list(m.classes_)),
             "confusion_matrix": confusion_matrix(yte, pred, labels=classes).tolist(), "train_seconds": round(time.time() - t, 2)}
        results.append({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})
        print(f"{name:30s} acc={r['accuracy']:.4f} f1={r['f1']:.4f}")
        if r["f1"] > best_f1: best, best_f1, best_name = m, r["f1"], name
    ART.mkdir(exist_ok=True)
    joblib.dump({"model": best, "classes": classes, "name": best_name}, ART / "text_model.joblib")
    lr = models["TF-IDF + Logistic Regression"]  # linear model => transparent per-word contributions (explainability)
    joblib.dump({"model": lr, "classes": classes}, ART / "text_explainer.joblib")
    (ART / "text_metrics.json").write_text(json.dumps({"best": best_name, "classes": classes, "samples": len(df), "results": results}, indent=2))
    print("best:", best_name)


if __name__ == "__main__":
    main()
