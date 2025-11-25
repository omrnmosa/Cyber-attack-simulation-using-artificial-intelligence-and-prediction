#!/usr/bin/env python3
from __future__ import annotations
import sys, json, urllib.parse, requests, pandas as pd
from pathlib import Path
# When running the script directly, the package root may not be on sys.path.
# Add the project root to sys.path so `import ml...` works reliably.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from ml.ml_utils import train as ml_train, score_findings, predict_from_findings

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data"
CSV = DATA / "dataset.csv"
REPORT_JSON = DATA / "ml_report.json"

def fetch_with_payload(url: str, payload: str):
    try:
        parts = list(urllib.parse.urlparse(url))
        qs = dict(urllib.parse.parse_qsl(parts[4], keep_blank_values=True))
        key = next((k for k in ["q","query","s","search","message","text","input"] if k in qs), "q")
        qs[key] = payload
        parts[4] = urllib.parse.urlencode(qs, doseq=True)
        test_url = urllib.parse.urlunparse(parts)
        r = requests.get(test_url, timeout=8)
        return test_url, r.status_code, r.text[:10000]
    except Exception as e:
        return url, 0, f"[error] {e}"

def main():
    print("=== Interactive URL + Payload Prediction ===")
    urls = []
    print("Enter target URLs (blank line to finish):")
    while True:
        u = input("> ").strip()
        if not u: break
        urls.append(u)
    if not urls:
        print("No URLs provided; exiting."); return

    print("\\nEnter payloads (blank line to finish). e.g., <script>alert(1)</script>, <b>inj</b>")
    payloads = []
    while True:
        p = input("payload> ").strip()
        if not p: break
        payloads.append(p)
    if not payloads:
        payloads = ["<script>alert(1)</script>", "<b>inj</b>"]

    findings = []
    for u in urls:
        for p in payloads:
            final_url, status, body = fetch_with_payload(u, p)
            findings.append({
                "kind":"unknown","vector":"link","url":final_url,"field":"q","payload":p,
                "evidence":"n/a","status":status, "text": f"{final_url} {p} {body[:500]}"
            })

    print("\\n[Training and printing preprocessing/training report...]")
    ml_train(verbose=True)

    risks, crits = score_findings(findings)
    labels = predict_from_findings(findings)

    print("\\n=== PREDICTIONS ===")
    for i,f in enumerate(findings,1):
        print(f"{i:02d}. URL: {f['url']}")
        print(f"    Payload: {f['payload']}")
        if i-1 < len(labels): print(f"    ML Label: {labels[i-1]}")
        if i-1 < len(risks):  print(f"    Risk %: {round(risks[i-1]*100)}")
        if i-1 < len(crits):  print(f"    Critical %: {round(crits[i-1]*100)}")

    # Dataset diagnostics
    miss = {}
    try:
        import pandas as pd
        df = pd.read_csv(CSV)
        miss = {c:int(df[c].isna().sum()) for c in df.columns}
    except Exception:
        pass

    # Training report
    rep = {}
    try:
        rep = json.loads((REPORT_JSON).read_text())
    except Exception:
        pass
    print("\\n=== TRAINING REPORT ===")
    if rep:
        rows = rep.get("rows")
        balance = rep.get("class_balance", {})
        cm = rep.get("metrics", {}).get("classification", {})
        reg = rep.get("metrics", {}).get("regression", {})
        print(f"Samples: {rows}")
        print(f"Class balance: {balance}")
        print(f"Classification: precision={cm.get('precision'):.3f}, recall={cm.get('recall'):.3f}, f1={cm.get('f1'):.3f}")
        print(f"Regression: MAE={reg.get('mae'):.3f}, R2={reg.get('r2'):.3f}")
    else:
        print("No ml_report.json metrics available yet.")

    print("\\n=== DATA QUALITY ===")
    if miss: print("Missing values per column:", miss)
    else: print("No dataset found or could not compute missing values.")

if __name__ == "__main__":
    main()
