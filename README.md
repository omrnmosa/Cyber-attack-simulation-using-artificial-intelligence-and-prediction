- AI-Driven website scanner — XSS & HTML Injection

- Scope:** Only XSS (reflected/stored) and HTML injection  
- storage:** Files (`data/scans.json`, `data/dataset.csv`) — no DB  
- Ethics:** Privacy-by-default masking, secrets/PII scrubbing, scope/blocklist, RAW toggle  
- Models:** GBR (risk) + Calibrated RF (critical), small RandomizedSearchCV, prints metrics  
- UI:** URL “Open” buttons, RAW toggle, charts + counts, delete scan/data, CSV/JSON exports

- Run
- bash
- pip install -r requirements.txt
- python app.py
- open http://127.0.0.1:5000

