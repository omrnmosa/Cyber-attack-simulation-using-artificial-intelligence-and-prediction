
"""
Compact ML utilities for the scanner

- Features: text TF‑IDF (char + word) + light URL numeric features
- Classifier: LogisticRegression (probabilities are calibrated by nature of LR)
- Regressor: RandomForestRegressor (robust, small code footprint)
- Provides:
    train(verbose=True)  -> trains on data/dataset.csv and prints a full report
    predict_from_findings(findings) -> severity labels
    score_findings(findings) -> (risk, critical_prob) lists for UI ordering
"""

from __future__ import annotations
from pathlib import Path
import pandas as pd, numpy as np, joblib, urllib.parse, json, warnings
from typing import List, Dict, Any
from scipy import sparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import precision_recall_fscore_support, mean_absolute_error, r2_score

warnings.filterwarnings("ignore")

DATA = Path("data")
CSV  = DATA/"dataset.csv"
CRIT = DATA/"crit_finding_clf.joblib"
RISK = DATA/"risk_finding_reg.joblib"
REPORT = DATA/"ml_report.json"



def _decode(s: str) -> str:
    try: return urllib.parse.unquote_plus(str(s))
    except Exception: return str(s)

def _row_to_text(row: dict) -> str:
    # Concatenate key fields; helps both XSS & HTML inj
    parts = [row.get("merged_url",""), row.get("evidence",""), row.get("vector",""),
             row.get("param",""), row.get("method","")]
    return " ".join(_decode(p) for p in parts if p)

_URL_NUM_COLS = ["len","num_digits","num_params","num_eq","num_pct","num_lt","num_gt","num_quotes",
                 "has_script","has_onerror","has_onload"]

def _url_num_vec(u: str) -> Dict[str,float]:
    u = _decode(u or "")
    return {
        "len": len(u),
        "num_digits": sum(c.isdigit() for c in u),
        "num_params": u.count("&") + u.count("?"),
        "num_eq": u.count("="),
        "num_pct": u.count("%"),
        "num_lt": u.count("<"),
        "num_gt": u.count(">"),
        "num_quotes": u.count("'") + u.count('"'),
        "has_script": int("script" in u.lower()),
        "has_onerror": int("onerror" in u.lower()),
        "has_onload": int("onload" in u.lower()),
    }

def _build_matrix(df: pd.DataFrame):
    texts = df.apply(lambda r: _row_to_text(r), axis=1).values

    # tiny, strong text signals
    char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5), min_df=1, max_features=12000)
    Xc = char_vec.fit_transform(texts)

    word_vec = TfidfVectorizer(analyzer="word", ngram_range=(1,2), min_df=1, max_features=8000, token_pattern=r"(?u)\b\w+\b")
    Xw = word_vec.fit_transform(texts)

    # numeric url stats
    U = pd.DataFrame([_url_num_vec(u) for u in df.get("merged_url","")], columns=_URL_NUM_COLS).fillna(0.0)
    Xu = sparse.csr_matrix(U.values.astype("float32"))

    X = sparse.hstack([Xc, Xw, Xu], format="csr")
    artifacts = {"char_vec": char_vec, "word_vec": word_vec, "url_cols": _URL_NUM_COLS}
    return X, artifacts

def _targets(df: pd.DataFrame):
    sev = df["severity"].astype(str).str.lower()
    # ensure plain NumPy arrays (not pandas ExtensionArray) for sklearn compatibility
    y_class = sev.isin(["high","critical"]).astype(int).to_numpy()
    sev_to_risk = {"info":0.1, "low":0.35, "medium":0.6, "high":0.85, "critical":0.95}
    y_risk = sev.map(sev_to_risk).fillna(0.5).to_numpy().astype(float)
    return y_class, y_risk



def train(verbose: bool=True):
    """Train small, strong models and save them. Optionally print a detailed report."""
    DATA.mkdir(exist_ok=True, parents=True)
    df = pd.read_csv(CSV)

    X, artifacts = _build_matrix(df)
    y_class, y_risk = _targets(df)

    # Models: compact & dependable
    clf = LogisticRegression(max_iter=200, class_weight="balanced", n_jobs=None)
    reg = RandomForestRegressor(n_estimators=120, random_state=13, n_jobs=-1)

    # CV metrics (sanity check)
    skf = StratifiedKFold(n_splits=min(5, max(2, int(np.sum(np.array(y_class))) if np.sum(np.array(y_class))>1 else 2)), shuffle=True, random_state=13)
    y_proba = cross_val_predict(clf, X.toarray(), np.array(y_class), cv=skf, method="predict_proba")[:,1]
    y_pred = (y_proba >= 0.5).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(y_class, y_pred, average="binary", zero_division=0)

    y_risk_pred = cross_val_predict(reg, X, y_risk, cv=3, method="predict")
    mae = mean_absolute_error(y_risk, y_risk_pred)
    r2 = r2_score(y_risk, y_risk_pred)

    # Fit final models and persist
    X_fit = sparse.csr_matrix(X)
    clf.fit(X_fit, y_class)
    reg.fit(X_fit, y_risk)
    joblib.dump({"model": clf, "artifacts": artifacts}, CRIT)
    joblib.dump({"model": reg, "artifacts": artifacts}, RISK)

    # determine number of features in a safe way (X may not always expose shape)
    try:
        n_features = int(X.shape[1]) if X is not None else 0
    except Exception:
        # fallback: derive from vectorizer artifacts if possible
        try:
            char_vec = artifacts.get("char_vec")
            word_vec = artifacts.get("word_vec")
            char_n = len(getattr(char_vec, "vocabulary_", {})) if char_vec is not None else 0
            word_n = len(getattr(word_vec, "vocabulary_", {})) if word_vec is not None else 0
            url_n = len(artifacts.get("url_cols", []))
            n_features = int(char_n + word_n + url_n)
        except Exception:
            n_features = 0

    report = {
        "rows": int(len(df)),
        "class_balance": {"critical_1": int(y_class.sum()), "critical_0": int(len(y_class) - int(y_class.sum()))},
        "metrics": {
            "classification": {"precision": float(prec), "recall": float(rec), "f1": float(f1), "threshold": 0.5},
            "regression": {"mae": float(mae), "r2": float(r2)},
        },
        "artifacts": {"char_features": n_features}
    }
    REPORT.write_text(json.dumps(report, indent=2))

    # Always log training results to analysis log
    from analysis_logger import log_ml_training
    artifacts = {"char_features": n_features, "url_cols": _URL_NUM_COLS}
    log_ml_training(report, artifacts)

def _matrix_for_findings(findings: List[dict], artifacts: Dict[str,Any]):
    texts = [_row_to_text(f) for f in findings]
    Xc = artifacts["char_vec"].transform(texts)
    Xw = artifacts["word_vec"].transform(texts)
    Xu = sparse.csr_matrix([list(_url_num_vec(f.get("merged_url","")).values()) for f in findings], dtype=float)
    return sparse.hstack([Xc, Xw, Xu], format="csr")

def predict_from_findings(findings: List[dict]) -> List[str]:
    """Return severity labels ('High'/'Medium') from current models."""
    if not findings: return []
    crit = joblib.load(CRIT); reg = joblib.load(RISK)  # ensure both exist
    X = _matrix_for_findings(findings, crit["artifacts"])
    probs = crit["model"].predict_proba(X)[:,1]
    labels = np.where(probs >= 0.5, "High", "Medium")
    return labels.tolist()

def score_findings(findings: List[dict]) -> tuple[list[float], list[float]]:
    """Return (risks, critical_probs)."""
    if not findings: return [], []
    crit = joblib.load(CRIT); risk = joblib.load(RISK)
    X = _matrix_for_findings(findings, crit["artifacts"])
    probs = crit["model"].predict_proba(X)[:,1]
    risks = risk["model"].predict(X)
    probs = np.clip(probs, 0, 1); risks = np.clip(risks, 0, 1)
    return risks.tolist(), probs.tolist()
