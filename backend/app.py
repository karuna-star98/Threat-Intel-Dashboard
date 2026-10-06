"""Flask REST API + static dashboard. SQLite storage. Run: python backend/app.py"""
import os, sys, csv, json, sqlite3, pathlib
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from services.ioc_validator import validate_indicator
from services.risk_engine import classify, interpret
from services.analysis import enrich_indicator, correlate_threats, generate_threat_alert, correlate_alerts

ROOT = pathlib.Path(__file__).resolve().parent.parent
API_KEY = os.environ.get("ANALYST_API_KEY", "demo-analyst-key")
INT = {"confidence_score", "risk_score", "observation_count"}
SEV_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = {"NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"}
ALERT_STATUSES = {"NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"}

def load_json(name): return json.loads((ROOT / "awareness" / name).read_text(encoding="utf-8"))

def init_db(path, threats_csv=None, vulns_csv=None):
    threats_csv = threats_csv or ROOT / "data" / "threat_intelligence_dataset.csv"
    vulns_csv = vulns_csv or ROOT / "data" / "vulnerabilities.csv"
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS threats(threat_id TEXT PRIMARY KEY, timestamp TEXT, threat_name TEXT, threat_category TEXT,
      indicator_type TEXT, indicator_value TEXT, source_name TEXT, source_reliability TEXT, confidence_score INTEGER,
      severity TEXT, risk_score INTEGER, status TEXT, first_seen TEXT, last_seen TEXT, country_or_region TEXT, description TEXT,
      mitre_tactic TEXT, mitre_technique TEXT, mitre_technique_id TEXT, cve_id TEXT, observation_count INTEGER,
      campaign_id TEXT, synthetic_label TEXT);
    CREATE INDEX IF NOT EXISTS ix_ind ON threats(indicator_value); CREATE INDEX IF NOT EXISTS ix_sev ON threats(severity);
    CREATE INDEX IF NOT EXISTS ix_cat ON threats(threat_category); CREATE INDEX IF NOT EXISTS ix_camp ON threats(campaign_id);
    CREATE TABLE IF NOT EXISTS vulnerabilities(cve_id TEXT PRIMARY KEY, product_category TEXT, severity TEXT, cvss_score REAL,
      published_date TEXT, patch_available INTEGER, exploitation_status_demo TEXT, asset_criticality INTEGER, exposure TEXT,
      priority_score INTEGER, description TEXT);
    CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, threat_id TEXT, timestamp TEXT, alert_type TEXT, severity TEXT,
      risk_score INTEGER, confidence_score INTEGER, description TEXT, status TEXT, observation_count INTEGER, indicator_value TEXT);
    CREATE TABLE IF NOT EXISTS analyst_notes(note_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, note TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS quiz_results(result_id INTEGER PRIMARY KEY AUTOINCREMENT, overall_score INTEGER, category_scores TEXT, created_at TEXT);
    """)
    if db.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 0 and pathlib.Path(threats_csv).exists():
        rows = list(csv.DictReader(open(threats_csv, encoding="utf-8")))
        cols = list(rows[0])
        db.executemany(f"INSERT INTO threats({','.join(cols)}) VALUES({','.join('?' * len(cols))})", [[r[c] for c in cols] for r in rows])
        for r in csv.DictReader(open(vulns_csv, encoding="utf-8")):
            db.execute("INSERT INTO vulnerabilities VALUES(?,?,?,?,?,?,?,?,?,?,?)", list(r.values()))
        db.row_factory = sqlite3.Row
        open_t = [dict(r) for r in db.execute("SELECT * FROM threats WHERE status IN ('NEW','UNDER_REVIEW','MONITORING')")]
        alerts = correlate_alerts([a for a in map(generate_threat_alert, open_t) if a])
        for n, a in enumerate(sorted(alerts, key=lambda x: -x["risk_score"]), 1):
            a["alert_id"] = f"ALT-{n:04d}"
            db.execute(f"INSERT INTO alerts({','.join(a)}) VALUES({','.join('?' * len(a))})", list(a.values()))
    db.commit(); db.close()

def create_app(db_path=None):
    app = Flask(__name__, static_folder=None)
    app.config["DB"] = str(db_path or ROOT / "data" / "ti.db")
    init_db(app.config["DB"])

    def q(sql, args=()):
        c = sqlite3.connect(app.config["DB"]); c.row_factory = sqlite3.Row
        try: return [dict(r) for r in c.execute(sql, args)]
        finally: c.close()
    def run(sql, args=()):
        c = sqlite3.connect(app.config["DB"])
        try:
            cur = c.execute(sql, args); c.commit(); return cur.rowcount
        finally: c.close()
    def err(msg, code): return jsonify({"error": msg}), code
    def authed(): return request.headers.get("X-API-Key") == API_KEY   # RBAC would extend this (viewer vs analyst)

    @app.get("/")
    def home(): return send_from_directory(ROOT / "frontend", "index.html")

    @app.get("/api/threats")
    def threats():
        w, a = [], []
        for col, key in (("severity", "severity"), ("threat_category", "category"), ("indicator_type", "indicator_type"), ("status", "status")):
            if request.args.get(key): w.append(f"{col}=?"); a.append(request.args[key])
        if request.args.get("min_risk"): w.append("risk_score>=?"); a.append(int(request.args["min_risk"]))
        if request.args.get("min_confidence"): w.append("confidence_score>=?"); a.append(int(request.args["min_confidence"]))
        if request.args.get("q"): w.append("(threat_name LIKE ? OR indicator_value LIKE ? OR threat_id LIKE ?)"); a += [f"%{request.args['q']}%"] * 3
        order = {"newest": "timestamp DESC", "risk": "risk_score DESC", "confidence": "confidence_score DESC", "observed": "observation_count DESC"}.get(request.args.get("sort", "newest"), "timestamp DESC")
        limit = min(int(request.args.get("limit", 50)), 500)
        rows = q(f"SELECT * FROM threats {'WHERE ' + ' AND '.join(w) if w else ''} ORDER BY {order} LIMIT ?", a + [limit])
        return jsonify(rows)

    @app.get("/api/threats/<tid>")
    def threat(tid):
        t = (q("SELECT * FROM threats WHERE threat_id=?", (tid,)) or [None])[0]
        if not t: return err("Threat not found", 404)
        same = q("SELECT * FROM threats WHERE indicator_value=?", (t["indicator_value"],))
        rel = q("SELECT * FROM threats WHERE campaign_id=?", (t["campaign_id"],))
        al = q("SELECT alert_id FROM alerts WHERE indicator_value=?", (t["indicator_value"],))
        notes = q("SELECT note, created_at FROM analyst_notes WHERE threat_id=? ORDER BY note_id", (tid,))
        t["enrichment"] = enrich_indicator(t["indicator_value"], same, al, rel, notes)
        t["interpretation"] = interpret(t["risk_score"], t["confidence_score"])
        t["cluster"] = (correlate_threats(rel) or [None])[0]
        t["notes"] = notes
        t["cve"] = q("SELECT * FROM vulnerabilities WHERE cve_id=?", (t["cve_id"],)) if t["cve_id"] else []
        t["timeline"] = [{"step": "First seen", "date": t["first_seen"]}, {"step": f"{t['observation_count']} observations", "date": t["last_seen"]},
                         {"step": f"Risk scored {t['risk_score']} ({t['severity']})", "date": t["last_seen"]}, {"step": f"Status: {t['status']}", "date": t["last_seen"]}]
        return jsonify(t)

    @app.post("/api/threats")
    def create_threat():
        if not authed(): return err("Unauthorized", 401)
        d = request.get_json(silent=True) or {}
        v = validate_indicator(d.get("indicator_value"))
        if not v["valid"]: return err(v["validation_notes"], 400)
        if d.get("severity") not in SEV_ORDER: return err("Invalid severity", 400)
        n = q("SELECT COUNT(*) c FROM threats")[0]["c"] + 1
        now = datetime.utcnow().isoformat(timespec="seconds"); tid = f"THR-2026-{n:03d}"
        run("INSERT INTO threats(threat_id,timestamp,threat_name,threat_category,indicator_type,indicator_value,source_name,source_reliability,confidence_score,severity,risk_score,status,first_seen,last_seen,description,observation_count,campaign_id,synthetic_label) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, now, str(d.get("threat_name", "Untitled"))[:120], d.get("threat_category", "PHISHING"), v["indicator_type"], v["normalized_value"],
             d.get("source_name", "Internal SOC"), "A", int(d.get("confidence_score", 50)), d["severity"], int(d.get("risk_score", 50)), "NEW",
             now[:10], now[:10], str(d.get("description", ""))[:500], 1, f"CMP-USER-{n}", "USER ENTERED"))
        return jsonify({"threat_id": tid}), 201

    @app.put("/api/threats/<tid>")
    def update_threat(tid):
        if not authed(): return err("Unauthorized", 401)
        st = (request.get_json(silent=True) or {}).get("status")
        if st not in STATUSES: return err("Invalid status", 400)
        return jsonify({"updated": run("UPDATE threats SET status=? WHERE threat_id=?", (st, tid))}) if q("SELECT 1 FROM threats WHERE threat_id=?", (tid,)) else err("Threat not found", 404)

    @app.get("/api/indicators/search")
    def search():
        val = request.args.get("q", "")
        v = validate_indicator(val)
        if not v["valid"]: return jsonify({**v, "known": False}), 400
        recs = q("SELECT * FROM threats WHERE indicator_value=? COLLATE NOCASE", (v["normalized_value"],))   # DB lookup ONLY - never connects
        rel = q("SELECT * FROM threats WHERE campaign_id=?", (recs[0]["campaign_id"],)) if recs else []
        al = q("SELECT alert_id FROM alerts WHERE indicator_value=?", (v["normalized_value"],))
        return jsonify(enrich_indicator(val, recs, al, rel))

    @app.get("/api/dashboard/stats")
    def stats():
        cnt = lambda col, tbl="threats": {r["k"]: r["n"] for r in q(f"SELECT {col} k, COUNT(*) n FROM {tbl} GROUP BY {col} ORDER BY n DESC")}
        t = q("SELECT COUNT(*) total, AVG(confidence_score) conf FROM threats")[0]
        sev = cnt("severity")
        risk = [r["risk_score"] for r in q("SELECT risk_score FROM threats")]; confs = [r["confidence_score"] for r in q("SELECT confidence_score FROM threats")]
        hist = lambda vals: {f"{i}-{i + 19}": sum(1 for v in vals if i <= v <= i + 19 + (i == 80)) for i in range(0, 100, 20)}
        qr = q("SELECT overall_score, category_scores FROM quiz_results")
        weak = {}
        for r in qr:
            for c, s in json.loads(r["category_scores"]).items(): weak.setdefault(c, []).append(s)
        return jsonify({"cards": {"total_threats": t["total"], "critical": sev.get("CRITICAL", 0), "high": sev.get("HIGH", 0),
            "active_indicators": q("SELECT COUNT(DISTINCT indicator_value) n FROM threats WHERE status IN ('NEW','UNDER_REVIEW','MONITORING')")[0]["n"],
            "open_investigations": q("SELECT COUNT(*) n FROM alerts WHERE status IN ('NEW','INVESTIGATING')")[0]["n"],
            "avg_confidence": round(t["conf"] or 0), "vulnerabilities": q("SELECT COUNT(*) n FROM vulnerabilities")[0]["n"]},
            "by_severity": sev, "by_category": cnt("threat_category"), "by_indicator_type": cnt("indicator_type"), "by_status": cnt("status"),
            "by_tactic": {k: v for k, v in cnt("mitre_tactic").items() if k}, "by_technique": {k: v for k, v in cnt("mitre_technique").items() if k},
            "risk_distribution": hist(risk), "confidence_distribution": hist(confs), "vuln_by_severity": cnt("severity", "vulnerabilities"),
            "vuln_by_category": cnt("product_category", "vulnerabilities"),
            "awareness": {"quizzes_taken": len(qr), "avg_score": round(sum(r["overall_score"] for r in qr) / len(qr)) if qr else None,
                          "weakest": sorted(((c, round(sum(v) / len(v))) for c, v in weak.items()), key=lambda x: x[1])[:3]}})

    @app.get("/api/dashboard/trends")
    def trends():
        return jsonify({r["m"]: r["n"] for r in q("SELECT substr(timestamp,1,7) m, COUNT(*) n FROM threats GROUP BY m ORDER BY m")})

    @app.get("/api/alerts")
    def alerts():
        return jsonify(q("SELECT * FROM alerts ORDER BY risk_score DESC LIMIT 200"))

    @app.put("/api/alerts/<aid>/status")
    def alert_status(aid):
        if not authed(): return err("Unauthorized", 401)
        st = (request.get_json(silent=True) or {}).get("status")
        if st not in ALERT_STATUSES: return err("Invalid status", 400)
        return jsonify({"updated": True}) if run("UPDATE alerts SET status=? WHERE alert_id=?", (st, aid)) else err("Alert not found", 404)

    @app.post("/api/threats/<tid>/notes")
    def add_note(tid):
        if not authed(): return err("Unauthorized", 401)
        note = str((request.get_json(silent=True) or {}).get("note", "")).strip()
        if not note or len(note) > 1000: return err("Note must be 1-1000 characters", 400)
        if not q("SELECT 1 FROM threats WHERE threat_id=?", (tid,)): return err("Threat not found", 404)
        run("INSERT INTO analyst_notes(threat_id,note,created_at) VALUES(?,?,?)", (tid, note, datetime.utcnow().isoformat(timespec="seconds")))
        return jsonify({"ok": True}), 201

    @app.get("/api/vulnerabilities")
    def vulns(): return jsonify(q("SELECT * FROM vulnerabilities ORDER BY priority_score DESC LIMIT 100"))

    @app.get("/api/awareness/modules")
    def modules(): return jsonify(load_json("modules.json"))

    @app.get("/api/quiz")
    def quiz():   # answers are NOT sent to the client
        return jsonify([{k: v for k, v in x.items() if k not in ("answer", "why")} for x in load_json("quiz_questions.json")])

    @app.post("/api/quiz/submit")
    def submit():
        ans = (request.get_json(silent=True) or {}).get("answers")
        if not isinstance(ans, dict) or not ans: return err("answers must be a non-empty object {question_id: option_index}", 400)
        res = score_quiz(load_json("quiz_questions.json"), ans)
        res["recommendations"] = generate_learning_recommendations(res["category_scores"], load_json("modules.json"))
        run("INSERT INTO quiz_results(overall_score,category_scores,created_at) VALUES(?,?,?)", (res["overall_score"], json.dumps(res["category_scores"]), datetime.utcnow().isoformat()))
        return jsonify(res)
    return app

def score_quiz(questions, answers):
    cat, review = {}, []
    for qn in questions:
        ok = answers.get(str(qn["id"])) == qn["answer"]
        c = cat.setdefault(qn["category"], [0, 0]); c[1] += 1; c[0] += ok
        review.append({"id": qn["id"], "correct": ok, "answer": qn["answer"], "why": qn["why"]})
    overall = round(100 * sum(c[0] for c in cat.values()) / max(1, sum(c[1] for c in cat.values())))
    band = "Needs Improvement" if overall <= 40 else "Basic Awareness" if overall <= 60 else "Good Awareness" if overall <= 80 else "Strong Awareness"
    return {"overall_score": overall, "band": band, "category_scores": {k: round(100 * v[0] / v[1]) for k, v in cat.items()}, "review": review,
            "disclaimer": "Educational score only - not an employee competency judgment."}

def generate_learning_recommendations(cat_scores, modules):
    out = []
    for c, s in sorted(cat_scores.items(), key=lambda x: x[1]):
        m = next((m["title"] for m in modules if m["category"] == c), None)
        out.append({"category": c, "score": s, "recommendation": f"Complete the '{m}' module." if s < 60 and m else
                    f"Review the '{m}' module." if s < 80 and m else "No immediate module required."})
    return out

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
