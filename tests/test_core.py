import sys, pathlib, tempfile, os
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
import pytest
from services.ioc_validator import validate_indicator as v
from services.risk_engine import *
from services.analysis import *
from app import create_app, score_quiz, generate_learning_recommendations, load_json

@pytest.fixture(scope="module")
def client():
    d = tempfile.mkdtemp()
    return create_app(os.path.join(d, "t.db")).test_client()
H = {"X-API-Key": "demo-analyst-key"}

@pytest.mark.parametrize("val,typ", [("198.51.100.25", "IP_ADDRESS"), ("2001:db8::1", "IP_ADDRESS"), ("login-check.invalid", "DOMAIN"),
    ("https://a.example.com/x", "URL"), ("d41d8cd98f00b204e9800998ecf8427e", "FILE_HASH"), ("a" * 40, "FILE_HASH"), ("b" * 64, "FILE_HASH"),
    ("cve-2099-1001", "CVE_ID"), ("user@example.org", "EMAIL_DOMAIN")])
def test_valid(val, typ): assert v(val)["valid"] and v(val)["indicator_type"] == typ
@pytest.mark.parametrize("val", ["999.1.1.1", "not a domain", "CVE-99-1", "", "ftp://x", "-bad-.com"])
def test_invalid(val): assert not v(val)["valid"]
def test_normalize(): assert v("CVE-2099-1001")["normalized_value"] == "CVE-2099-1001" and v("EXAMPLE.com")["normalized_value"] == "example.com"
def test_classify():
    assert [classify(x) for x in (0, 20, 21, 40, 41, 60, 61, 80, 81, 100)] == ["INFORMATIONAL"] * 2 + ["LOW"] * 2 + ["MEDIUM"] * 2 + ["HIGH"] * 2 + ["CRITICAL"] * 2
def test_risk_bounds_and_order():
    hi = calculate_threat_risk("CRITICAL", 95, 0, 15, "A", 4); lo = calculate_threat_risk("LOW", 20, 200, 1, "D", 0)
    assert 0 <= lo < hi <= 100
def test_confidence_and_reliability():
    assert calculate_confidence("A", 3, 0) > calculate_confidence("D", 0, 100); assert SOURCES["Internal SOC"] == "A" and SOURCES["Unknown Source"] == "D"
def test_risk_vs_confidence(): assert "weak" in interpret(90, 25) and "High-confidence" in interpret(70, 95)
def test_vuln_priority():
    assert calculate_vulnerability_priority(9.8, 20, "isolated", False) < calculate_vulnerability_priority(7.5, 100, "internet", True)
REC = {"threat_id": "T1", "timestamp": "x", "threat_name": "n", "threat_category": "PHISHING", "indicator_value": "a.example.com", "risk_score": 80,
       "confidence_score": 90, "severity": "HIGH", "observation_count": 2, "first_seen": "2026-01-01", "last_seen": "2026-02-01", "status": "NEW",
       "mitre_tactic": "", "mitre_technique": "", "mitre_technique_id": "", "campaign_id": "C1", "indicator_type": "DOMAIN"}
def test_alert_rules():
    assert generate_threat_alert(REC)["alert_type"] == "HIGH_RISK_HIGH_CONFIDENCE"
    assert generate_threat_alert({**REC, "confidence_score": 20})["alert_type"] == "HIGH_RISK_LOW_CONFIDENCE"
    assert generate_threat_alert({**REC, "risk_score": 30}) is None
def test_alert_correlation():
    a = generate_threat_alert({**REC, "observation_count": 1}); out = correlate_alerts([dict(a) for _ in range(100)])
    assert len(out) == 1 and out[0]["observation_count"] == 100
def test_enrich_unknown_and_known():
    assert enrich_indicator("203.0.113.9", [])["known"] is False
    e = enrich_indicator("a.example.com", [REC], related=[REC, {**REC, "indicator_value": "1.example.net"}]); assert e["known"] and e["related_indicators"] == ["1.example.net"]
def test_correlate_threats():
    c = correlate_threats([REC, {**REC, "indicator_value": "192.0.2.1", "indicator_type": "IP_ADDRESS"}]); assert c[0]["cluster"] == "RELATED THREAT CLUSTER"
def test_empty_dataset():
    assert enrich_indicator("x.example.com", [])["known"] is False and correlate_alerts([]) == [] and correlate_threats([]) == []
def test_quiz_scoring():
    qs = load_json("quiz_questions.json"); assert len(qs) >= 18
    perfect = score_quiz(qs, {str(q["id"]): q["answer"] for q in qs}); assert perfect["overall_score"] == 100 and perfect["band"] == "Strong Awareness"
    assert score_quiz(qs, {"1": 99})["overall_score"] == 0
def test_recommendations():
    r = generate_learning_recommendations({"Phishing": 40, "Passwords": 90}, load_json("modules.json"))
    assert "Complete" in r[0]["recommendation"] and "No immediate" in r[1]["recommendation"]
def test_api_threats_filter_sort(client):
    r = client.get("/api/threats?severity=HIGH&sort=risk&limit=20").json; assert r and all(t["severity"] == "HIGH" for t in r)
    assert [t["risk_score"] for t in r] == sorted((t["risk_score"] for t in r), reverse=True)
    assert all(t["threat_category"] == "PHISHING" for t in client.get("/api/threats?category=PHISHING").json)
def test_demo_scenario_and_detail(client):
    d = client.get("/api/threats/THR-2026-001").json
    assert d["indicator_value"] == "login-check.invalid" and "198.51.100.25" in d["enrichment"]["related_indicators"] and d["risk_score"] == 78
    assert client.get("/api/threats/NOPE").status_code == 404
def test_search(client):
    r = client.get("/api/indicators/search?q=198.51.100.25").json; assert r["known"] and r["indicator_type"] == "IP_ADDRESS"
    assert client.get("/api/indicators/search?q=%25bad").status_code == 400
def test_stats_and_trends(client):
    assert client.get("/api/dashboard/stats").json["cards"]["total_threats"] == 2000 and client.get("/api/dashboard/trends").json
def test_auth_notes_alert_status(client):
    assert client.post("/api/threats/THR-2026-001/notes", json={"note": "x"}).status_code == 401
    assert client.post("/api/threats/THR-2026-001/notes", json={"note": "checked"}, headers=H).status_code == 201
    assert client.post("/api/threats/THR-2026-001/notes", json={"note": ""}, headers=H).status_code == 400
    assert client.get("/api/threats/THR-2026-001").json["notes"][0]["note"] == "checked"
    aid = client.get("/api/alerts").json[0]["alert_id"]
    assert client.put(f"/api/alerts/{aid}/status", json={"status": "RESOLVED"}, headers=H).status_code == 200
    assert client.put(f"/api/alerts/{aid}/status", json={"status": "BAD"}, headers=H).status_code == 400
def test_create_threat_validation(client):
    assert client.post("/api/threats", json={"indicator_value": "bad!!", "severity": "HIGH"}, headers=H).status_code == 400
    assert client.post("/api/threats", json={"indicator_value": "new.example.com", "severity": "HIGH"}, headers=H).status_code == 201
def test_quiz_api_hides_answers_and_persists(client):
    assert all("answer" not in q for q in client.get("/api/quiz").json)
    assert client.post("/api/quiz/submit", json={"answers": {}}).status_code == 400
    assert client.post("/api/quiz/submit", json={"answers": {"1": 2}}).status_code == 200
    assert client.get("/api/dashboard/stats").json["awareness"]["quizzes_taken"] == 1
def test_modules_and_vulns(client):
    assert len(client.get("/api/awareness/modules").json) >= 7 and client.get("/api/vulnerabilities").json[0]["priority_score"] >= client.get("/api/vulnerabilities").json[-1]["priority_score"]
