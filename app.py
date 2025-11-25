"""
AI-Driven Website Security Scanner
--------------------------------

An ML-powered web security scanner focused on XSS and HTML injection vulnerabilities.
Implements strong privacy controls and ethical scanning practices.

Core Components:
1. Scanner - Crawls and tests for vulnerabilities
2. Ethics Policy - Privacy and security controls
3. ML Analysis - Risk scoring and classification
4. Logging - Separate analysis and training output
"""

from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, send_file
from scanner import Scanner
from ethics import EthicsPolicy
from ml.ml_utils import train as ml_train, score_findings
from analysis_logger import log_ml_training, log_scan_analysis, logger
import threading
import json
import csv
from pathlib import Path
from datetime import datetime

def _load_scans():
    """Helper to load scans from JSON file."""
    return json.loads(SCANS_FILE.read_text(encoding="utf-8"))

def _analytics(findings):
    """Helper to compute analytics for report."""
    risk_scores = [f.get("risk_score", 0.3) for f in findings]
    crit_scores = [f.get("crit_score", 0.2) for f in findings]
    risk_pct = int(round(max(risk_scores, default=0.3) * 100))
    crit_pct = int(round(max(crit_scores, default=0.2) * 100))
    
    # Get unique labels and their corresponding scores
    labels = []
    risks = []
    crits = []
    for f in findings:
        label = f.get("type", "unknown")
        if label not in labels:
            labels.append(label)
            risks.append(f.get("risk_score", 0.3))
            crits.append(f.get("crit_score", 0.2))
            
    return risk_pct, crit_pct, labels, risks, crits

app = Flask(__name__, template_folder="templates", static_folder="static")

# Initialize data storage
DATA_DIR = Path("data")
SCANS_FILE = DATA_DIR / "scans.json"
CSV_FILE = DATA_DIR / "dataset.csv"
DATA_DIR.mkdir(exist_ok=True)

# Ensure scans.json exists
if not SCANS_FILE.exists():
    SCANS_FILE.write_text("[]", encoding="utf-8")

# Initialize dataset.csv with schema
if not CSV_FILE.exists():
    with CSV_FILE.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "scan_id", "type", "severity", "method", "vector",
            "param", "status", "evidence", "merged_url", "timestamp"
        ])

# Initialize ethics policy with enhanced controls
POLICY = EthicsPolicy(
    mask_payloads=True,
    scope_host="",  # e.g. "example.com" to restrict scope
    blocklist_hosts=set(),
    query_deny={
        "password", "token", "auth", "apikey", "key",
        "secret", "credentials", "session", "jwt"
    },
    query_allow=set(),
    rate_limit=None  # Use default rate limiting
)

# Simple job store for progress polling
JOBS = {}

# ---------- Helpers ----------
def save_scan(scan: dict) -> None:
    """Append a completed scan to scans.json."""
    scans = json.loads(SCANS_FILE.read_text(encoding="utf-8"))
    scans.append(scan)
    SCANS_FILE.write_text(json.dumps(scans, indent=2), encoding="utf-8")

def append_findings_to_csv(scan_id: int, findings: list) -> None:
    """Append RAW findings rows to dataset.csv (never masked/hashed)."""
    ts = datetime.utcnow().isoformat()
    with CSV_FILE.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for fnd in findings:
            t = fnd.get("type","")
            # display severity; used for charts and baseline labels
            sev = "High" if t.startswith("xss") else ("Medium" if t=="html_injection" else "Info")
            # IMPORTANT: merged_url for dataset stays RAW (attack_url OR page OR payload)
            merged = fnd.get("attack_url") or fnd.get("page") or fnd.get("payload","")
            w.writerow([
                scan_id, t, sev,
                fnd.get("method",""), fnd.get("vector",""), fnd.get("param",""),
                fnd.get("status",""), fnd.get("evidence",""), merged, ts
            ])

def _new_job():
    """Create a job id and initial job state."""
    import uuid
    jid = uuid.uuid4().hex[:10]
    JOBS[jid] = {"status":"queued","progress":0,"scan_id":None,"error":None}
    return jid

# ---------- Routes ----------
@app.get("/")
def home():
    """Landing page with one input + recent 10 scans."""
    scans = list(reversed(json.loads(SCANS_FILE.read_text(encoding="utf-8"))))[:10]
    return render_template("home.html", scans=scans, title="AI-Driven website scanner")

@app.post("/start")
def start():
    """Kick off a background scan and return a job id for polling."""
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    max_pages = int(data.get("max_pages") or 20)
    timeout   = int(data.get("timeout") or 8)

    # Ethics gate: format, domain scope, blocklist
    ok, msg = POLICY.check(url)
    if not ok:
        return {"error": msg}, 400

    jid = _new_job()
    JOBS[jid]["status"] = "starting"

    def progress_cb(done, total):
        """Update progress so the UI progress bar moves smoothly."""
        JOBS[jid].update(
            progress=int(100 * min(done, total) / max(1, total)),
            status=f"Scanning… {done}/{total}"
        )

    def run():
        try:
            # 1) Crawl & test (RAW in memory)
            s = Scanner(url, max_pages=max_pages, timeout=timeout, progress_cb=progress_cb)
            s.crawl()
            findings = [f.__dict__ for f in s.findings]

            # 2) Write dataset rows (RAW) and (re)train models
            try:
                append_findings_to_csv(scan_id=0, findings=findings)  # temp rows for now
                ml_train(verbose=True)
            except Exception as e:
                print("Training error:", e)

            # 3) Per-finding scores for UI + advice
            pf_risk, pf_crit = score_findings(findings)
            for i, f in enumerate(findings):
                f["risk_score"] = float(pf_risk[i]) if i < len(pf_risk) else 0.3
                f["crit_score"] = float(pf_crit[i]) if i < len(pf_crit) else 0.2
                # minimal advice by type
                if f.get("type") == "xss_stored":
                    f["advice"] = "Stored XSS is critical: sanitize stored content, encode on render; enforce strict CSP."
                elif f.get("type") == "xss_reflected":
                    f["advice"] = "Reflected XSS: contextual output encoding + input validation; add CSP with reporting."
                else:
                    f["advice"] = "HTML injection: allowlist sanitizer; treat input as text; avoid raw innerHTML."

            # 4) Aggregate scan-level predictions (summary numbers for the scan)
            # Use per-finding scores computed above to derive scan-level metrics.
            # `predict_from_findings` returns a list of labels, not two floats —
            # so compute numeric summaries here instead.
            if pf_risk:
                risk = float(max(pf_risk))
            else:
                risk = 0.3
            if pf_crit:
                critical = float(max(pf_crit))
            else:
                critical = 0.2

            # 5) Persist scan (assign final id now)
            scans = json.loads(SCANS_FILE.read_text(encoding="utf-8"))
            sid = (scans[-1]["id"] + 1) if scans else 1
            scan = {
                "id": sid,
                "url": url,
                "ts": datetime.utcnow().isoformat(),
                "risk": risk,
                "critical_prob": critical,
                "findings": findings,
                "pages_limit": max_pages,
                "timeout": timeout,
                "duration": 0  # TODO: Track actual duration
            }
            save_scan(scan)

            # 6) Update temp dataset rows (id 0) to real id
            rows = []
            with CSV_FILE.open("r", encoding="utf-8") as f:
                r = csv.reader(f)
                header = next(r, None)
                for row in r:
                    if row and row[0] == "0":
                        row[0] = str(sid)
                    rows.append(row)
            with CSV_FILE.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["scan_id","type","severity","method","vector","param","status","evidence","merged_url","timestamp"])
                w.writerows(rows)

            # Log detailed scan analysis
            log_scan_analysis(sid, findings, risk, critical)
            
            JOBS[jid].update(status="done", progress=100, scan_id=sid)

        except Exception as e:
            JOBS[jid].update(status="error", error=str(e))
            logger.exception("Scan failed")

    threading.Thread(target=run, daemon=True).start()
    return {"job": jid}

@app.get("/job/<jid>")
def job(jid):
    """Client polls here to update spinner & bar."""
    return JOBS.get(jid, {"error":"unknown job"})

@app.get("/results/<int:scan_id>")
def results(scan_id: int):
    """Results page (masked by default)."""
    scans = json.loads(SCANS_FILE.read_text(encoding="utf-8"))
    scan = next((s for s in scans if s["id"] == scan_id), None)
    if not scan:
        return render_template("error.html", message="Scan not found"), 404

    # Ethics scrubbing for UI
    masked = POLICY.scrub(scan["findings"], show_raw=False)

    # Enrich data for UI (severity, fix, masked merged_url)
    SEV = {"xss_reflected":("High","danger"), "xss_stored":("High","danger"), "html_injection":("Medium","warning")}
    FIX = {"xss_reflected":"Encode output, validate input, enforce CSP.",
           "xss_stored":"Sanitize stored content, validate inputs, restrict UGC, enforce CSP.",
           "html_injection":"Treat untrusted data as text; allowlist sanitizer."}
    enriched = []
    for f in masked:
        t = f.get("type","")
        sev, color = SEV.get(t, ("Info","secondary"))
        f["severity"] = sev
        f["severity_color"] = color
        f["fix"] = FIX.get(t, "Validate & encode outputs.")
        f["merged_url"] = f.get("attack_url") or f.get("page") or f.get("payload_hash","")
        enriched.append(f)

    # Charts: donut (type) & histogram (severity)
    counts = {"XSS (refl)":0, "XSS (stored)":0, "HTML inj":0}
    for f in enriched:
        if f["type"] == "xss_reflected": counts["XSS (refl)"] += 1
        elif f["type"] == "xss_stored":  counts["XSS (stored)"] += 1
        elif f["type"] == "html_injection": counts["HTML inj"] += 1
    donut_labels = [k for k,v in counts.items() if v] or ["none"]
    donut_values = [v for _,v in counts.items() if v] or [1]

    sev_counts = {"High":0, "Medium":0, "Info":0}
    for f in enriched:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"],0)+1
    hist_labels = ["High","Medium","Info"]
    hist_values = [int(sev_counts.get(k,0)) for k in hist_labels]

    import json as _json
    return render_template(
        "results.html",
        scan=scan, findings=enriched,
        risk_pct=int(round(scan["risk"]*100)),
        crit_pct=int(round(scan["critical_prob"]*100)),
        donut_labels=_json.dumps(donut_labels), donut_values=_json.dumps(donut_values),
        hist_labels=_json.dumps(hist_labels), hist_values=_json.dumps(hist_values),
        title="AI-Driven website scanner"
    )

@app.get("/results/<int:scan_id>/raw_rows")
def raw_rows(scan_id: int):
    """Return masked & RAW merged URLs so the client can toggle locally."""
    scans = json.loads(SCANS_FILE.read_text(encoding="utf-8"))
    scan = next((s for s in scans if s["id"] == scan_id), None)
    if not scan:
        return jsonify({"error":"not found"}), 404

    raw = scan["findings"]
    masked = POLICY.scrub(raw, show_raw=False)

    def merged(lst, raw_mode=False):
        return [
            (f.get("attack_url") or f.get("page") or (f.get("payload") if raw_mode else f.get("payload_hash","")))
            for f in lst
        ]
    return jsonify({"masked": merged(masked, False), "raw": merged(raw, True)})

@app.get("/export/<int:scan_id>.json")
def export_json(scan_id: int):
    """Export JSON (masked by default; add ?raw=1 to reveal)."""
    scans = json.loads(SCANS_FILE.read_text(encoding="utf-8"))
    scan = next((s for s in scans if s["id"] == scan_id), None)
    if not scan:
        return jsonify({"error":"not found"}), 404
    show_raw = (request.args.get("raw") == "1")
    safe = POLICY.scrub(scan["findings"], show_raw=show_raw)
    return jsonify({"meta":{"url":scan["url"],"risk":scan["risk"],"critical_prob":scan["critical_prob"]},
                    "count":len(safe), "findings":safe})

@app.get("/export/<int:scan_id>.csv")
def export_csv(scan_id: int):
    """Export CSV (masked by default; add ?raw=1 to reveal)."""
    scans = json.loads(SCANS_FILE.read_text(encoding="utf-8"))
    scan = next((s for s in scans if s["id"] == scan_id), None)
    if not scan:
        return Response("not found", status=404)
    show_raw = (request.args.get("raw") == "1")
    safe = POLICY.scrub(scan["findings"], show_raw=show_raw)
    out = [["type","severity","method","vector","param","status","evidence","merged_url"]]
    SEV = {"xss_reflected":"High","xss_stored":"High","html_injection":"Medium"}
    for f in safe:
        merged = f.get("attack_url") or f.get("page") or f.get("payload_hash","")
        out.append([f.get("type",""), SEV.get(f.get("type",""),"Info"), f.get("method",""), f.get("vector",""),
                    f.get("param",""), f.get("status",""), f.get("evidence",""), merged])
    import io, csv as _csv
    buf = io.StringIO()
    _csv.writer(buf).writerows(out)
    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.csv' + '"'  # close quote safely
    return resp

@app.post("/delete_all")
def delete_all():
    """Clear all scans & dataset (useful for class resets)."""
    SCANS_FILE.write_text("[]", encoding="utf-8")
    with CSV_FILE.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scan_id","type","severity","method","vector","param","status","evidence","merged_url","timestamp"])
    return redirect(url_for("home"))

@app.post("/delete_scan/<int:scan_id>")
def delete_scan(scan_id: int):
    """Delete one scan + its dataset rows."""
    scans = json.loads(SCANS_FILE.read_text(encoding="utf-8"))
    scans = [s for s in scans if s.get("id") != scan_id]
    SCANS_FILE.write_text(json.dumps(scans, indent=2), encoding="utf-8")

    rows = []
    import csv as _csv
    with CSV_FILE.open("r", encoding="utf-8") as f:
        r = _csv.reader(f); header = next(r, None)
        for row in r:
            try: sid = int(row[0])
            except Exception: sid = None
            if sid != scan_id: rows.append(row)
    with CSV_FILE.open("w", newline="", encoding="utf-8") as f:
        w = _csv.writer(f)
        w.writerow(["scan_id","type","severity","method","vector","param","status","evidence","merged_url","timestamp"])
        w.writerows(rows)
    return redirect(url_for("home"))


# --- ML retraining hook: run after each scan and print preprocessing/training details to terminal
@app.route("/retrain_after_scan/<int:scan_id>", methods=["POST"])
def retrain_after_scan(scan_id: int):
    print(f"\n[Scan {scan_id}] Training models and printing full preprocessing/analysis report...")
    try:
        ml_train(verbose=True)
        return jsonify({"ok": True}), 200
    except Exception as e:
        print("[ML] retrain failed:", e)
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/report/<int:scan_id>.pdf")
def report(scan_id: int):
    from io import BytesIO
    buffer = BytesIO()
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import cm

    scans = _load_scans()
    scan = next((s for s in scans if s["id"]==scan_id), None)
    if not scan: return redirect(url_for("home"))

    vulns = scan["findings"]
    risk_pct, crit_pct, labels, risks, crits = _analytics(vulns)

    rep = {}
    try:
        rep = json.loads((DATA_DIR/'ml_report.json').read_text())
    except Exception:
        pass

    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4; y = height - 2*cm
    def line(txt, dy=0.6):
        nonlocal y
        c.drawString(2*cm, y, str(txt)); y -= dy*cm

    c.setFont("Helvetica-Bold", 14); line("AI Magical Scanner — Full Report")
    c.setFont("Helvetica", 10)
    line(f"Target: {scan.get('url', 'N/A')}")
    line(f"Pages: {scan.get('pages_limit', 'N/A')}  Timeout: {scan.get('timeout', 'N/A')}s  Duration: {scan.get('duration', 'N/A')}s")

    c.setFont("Helvetica-Bold", 12); line("Analytics:")
    c.setFont("Helvetica", 10)
    line(f"Risk Score: {risk_pct}%")
    line(f"Critical Probability: {crit_pct}%")

    c.setFont("Helvetica-Bold", 12); line("Model Metrics:")
    if rep:
        m = rep.get("metrics",{}); cls = m.get("classification",{}); reg = m.get("regression",{})
        line(f"Precision: {cls.get('precision',0):.3f}")
        line(f"Recall: {cls.get('recall',0):.3f}")
        line(f"F1 Score: {cls.get('f1',0):.3f}")
        line(f"MAE: {reg.get('mae',0):.3f}")
        line(f"R2: {reg.get('r2',0):.3f}")
        line(f"Class Balance: {rep.get('class_balance',{})}")
        line(f"Samples: {rep.get('rows',0)}")
    else:
        line("No training report available yet.")

    # Dataset missing values
    try:
        import pandas as pd
        df = pd.read_csv(DATA_DIR/'dataset.csv')
        miss = {c:int(df[c].isna().sum()) for c in df.columns}
        line("Data Preprocessing & Quality:")
        line(f"Columns: {list(df.columns)}")
        line(f"Missing values per column: {miss}")
    except Exception:
        line("Could not read dataset.csv for preprocessing details.")

    c.setFont("Helvetica-Bold", 12); line("Findings:")
    c.setFont("Helvetica", 9)
    for i, v in enumerate(vulns, 1):
        if y < 3*cm: c.showPage(); y = height - 2*cm; c.setFont("Helvetica", 9)
        line(f"{i}. {v.get('kind','?')} — {v.get('url','')}")
        line(f"    Field: {v.get('field','')}  Evidence: {v.get('evidence','')}  Status: {v.get('status','')}  ML: {v.get('ml_label','')} (Risk {v.get('risk','?')}% / Crit {v.get('crit','?')}%)", 0.5)

    c.showPage(); c.save(); buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"report_{scan_id}.pdf", mimetype="application/pdf")

if __name__ == "__main__":
    app.run(debug=True)
