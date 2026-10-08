# Machine learning

**URL model** – 24 numeric features (length, dots, subdomains, hyphens, digits, special chars, `@`, IP host, HTTPS, keyword count, suspicious TLD, entropy, brand hit/typo, punycode, shortener, port, executable extension…). Classes: safe / suspicious / phishing / malicious. Candidates: Logistic Regression, Random Forest, XGBoost. The best macro-F1 model is saved to `ml/artifacts/url_model.joblib`.

**Text model** – TF-IDF (1–2 grams) with Logistic Regression, Naive Bayes, Random Forest across 9 classes (8 scam types + legitimate). A linear explainer model exposes per-word contributions ("words that pushed the decision"). `python -m ml.shap_report` produces global SHAP importances for the URL model.

**Metrics** – accuracy, macro precision/recall/F1, one-vs-rest ROC-AUC and confusion matrices are written to `ml/artifacts/*_metrics.json` and shown on the admin dashboard.

**Data** – bundled generators are synthetic (offline demo, 3–5% label noise). For your report, retrain on real data: Tranco top-1M (safe), PhishTank/OpenPhish (phishing), URLhaus (malicious), SMS Spam Collection and phishing-email corpora. Keep a held-out test split and report those metrics.

**Advanced option (BERT)** – fine-tune `distilbert-base-uncased` on `ml/data/messages.csv` with Hugging Face `Trainer`, export to `ml/artifacts/bert/`, and add it as another signal key (`nlp_bert`) in `risk_engine/config.json` weights.
