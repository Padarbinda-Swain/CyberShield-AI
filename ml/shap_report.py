"""Optional global SHAP report for the deployed URL model -> ml/artifacts/url_shap.json"""
import json, pathlib
import joblib, numpy as np, pandas as pd, shap
from url_scanner.features import FEATURE_NAMES, extract_features

ART = pathlib.Path(__file__).parent / "artifacts"
b = joblib.load(ART / "url_model.joblib")
df = pd.read_csv(pathlib.Path(__file__).parent / "data" / "urls.csv").sample(400, random_state=1)
X = pd.DataFrame([extract_features(u) for u in df.url])[FEATURE_NAMES]
est = b["model"].steps[-1][1] if hasattr(b["model"], "steps") else b["model"]
sv = shap.TreeExplainer(est).shap_values(X)
arr = np.abs(np.array(sv)).mean(axis=(0, 1)) if isinstance(sv, list) else np.abs(sv).mean(axis=tuple(i for i in range(sv.ndim) if i != 1))
out = dict(sorted(zip(FEATURE_NAMES, map(float, arr)), key=lambda t: -t[1]))
(ART / "url_shap.json").write_text(json.dumps(out, indent=2)); print(list(out.items())[:6])
