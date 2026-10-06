# Cybersecurity Awareness & Threat Intelligence Dashboard

Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive awareness training.

> This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems. All data is SYNTHETIC / DEMO ONLY (RFC 5737 IPs, example.* / .invalid domains, random fake hashes, CVE-2099-* IDs).

## Run it
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python data/generate_threat_data.py                    # 2,000 threat records + 60 vulnerabilities
python backend/app.py                                  # DB is created automatically on first start
# open http://127.0.0.1:5000
python -m pytest -q tests                              # 36 tests
```
Try: IOC Search -> `198.51.100.25`; Threats -> click `THR-2026-001` (demo scenario, `login-check.invalid`); Quiz -> submit -> see score + recommendations.

## Architecture
Synthetic CSV -> SQLite (`threats`, `vulnerabilities`, `alerts`, `analyst_notes`, `quiz_results`) -> services (`ioc_validator`, `risk_engine`, `analysis`) -> Flask REST API -> single-page SOC dashboard. Awareness content lives in `awareness/*.json`.

## Key concepts implemented
- **Validation** checks syntax only, not maliciousness. **IOC match != confirmed compromise.**
- **Risk** (severity 30%, confidence 25%, recency 15%, frequency 10%, source reliability 10%, context 10%) is separate from **Confidence** (evidence quality).
- **Correlation** groups by campaign into RELATED THREAT CLUSTERs (relationship, not attribution). **Alert correlation** merges repeats into one alert with an observation count (anti alert-fatigue).
- **ATT&CK** mapping only when confidence >= 50 and the category implies behavior (T1566, T1071, T1486, T1110, T1190, T1046, T1567, T1078).
- **Vulnerability priority** = CVSS + asset criticality + exposure + exploitation evidence.
- Search is a database lookup only. Nothing is ever visited or contacted.

## API
`GET /api/threats` (filters: severity, category, indicator_type, status, min_risk, min_confidence, q, sort=newest|risk|confidence|observed) · `GET/PUT /api/threats/<id>` · `POST /api/threats` · `POST /api/threats/<id>/notes` · `GET /api/indicators/search?q=` · `GET /api/dashboard/stats|trends` · `GET /api/alerts` · `PUT /api/alerts/<id>/status` · `GET /api/vulnerabilities` · `GET /api/awareness/modules` · `GET /api/quiz` · `POST /api/quiz/submit`
Write endpoints need header `X-API-Key` (env `ANALYST_API_KEY`, default `demo-analyst-key`).

## Limitations / future work
Synthetic data only; single shared API key (no full RBAC/rate limiting); add STIX/TAXII, CISA KEV, SIEM/SOAR, IOC expiry, HTTPS, Docker.
