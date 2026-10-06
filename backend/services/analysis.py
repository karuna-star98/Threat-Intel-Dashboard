"""Enrichment, correlation, alerts. All LOCAL data - no network calls."""
from .ioc_validator import validate_indicator

ACTIONS = {
 "PHISHING": ["Review related internal logs", "Check for authorized sightings", "Review email-security telemetry", "Increase phishing awareness", "Monitor for related indicators"],
 "RANSOMWARE": ["Verify offline backups", "Review patch status", "Check endpoint protection alerts"],
 "VULNERABILITY EXPOSURE": ["Check asset inventory for affected product", "Prioritize patching by exposure"],
}
DEFAULT_ACTIONS = ["Review related internal logs", "Validate indicator and source reliability", "Monitor for related indicators"]

def enrich_indicator(value, records, alerts=(), related=(), notes=()):
    v = validate_indicator(value)
    recs = list(records)
    if not recs:
        return {**v, "known": False, "note": "Not in local demo dataset (lookup only, nothing was contacted)."}
    top = max(recs, key=lambda r: r["risk_score"])
    return {**v, "known": True, "first_seen": min(r["first_seen"] for r in recs), "last_seen": max(r["last_seen"] for r in recs),
            "categories": sorted({r["threat_category"] for r in recs}),
            "confidence": round(sum(r["confidence_score"] for r in recs) / len(recs)),
            "severity": top["severity"], "risk_score": top["risk_score"], "status": top["status"],
            "observations": sum(r["observation_count"] for r in recs), "records": len(recs),
            "related_alerts": [a["alert_id"] for a in alerts],
            "related_indicators": sorted({r["indicator_value"] for r in related if r["indicator_value"] != v["normalized_value"]}),
            "mitre": [{"tactic": r["mitre_tactic"], "technique": r["mitre_technique"], "id": r["mitre_technique_id"]}
                      for r in recs if r["mitre_tactic"]][:1],
            "analyst_notes": [n["note"] for n in notes],
            "recommended_actions": ACTIONS.get(top["threat_category"], DEFAULT_ACTIONS)}

def correlate_threats(rows, min_indicators=2):
    """Group by campaign_id -> RELATED THREAT CLUSTER. Shows relationship, NOT attribution."""
    groups = {}
    for r in rows:
        groups.setdefault(r["campaign_id"], []).append(r)
    out = []
    for cid, g in groups.items():
        inds = {(r["indicator_type"], r["indicator_value"]) for r in g}
        if len(inds) >= min_indicators:
            out.append({"cluster": "RELATED THREAT CLUSTER", "campaign_id": cid, "category": g[0]["threat_category"],
                        "indicators": sorted(inds), "note": "Correlation shows relationship, not proof of attribution."})
    return out

def generate_threat_alert(t, risk_thr=70, conf_thr=60, obs_thr=5):
    kind = None
    if t["risk_score"] >= risk_thr and t["confidence_score"] >= conf_thr: kind = "HIGH_RISK_HIGH_CONFIDENCE"
    elif t["risk_score"] >= risk_thr: kind = "HIGH_RISK_LOW_CONFIDENCE"
    elif t["observation_count"] >= obs_thr and t["confidence_score"] >= conf_thr: kind = "REPEATED_OBSERVATION"
    elif t["threat_category"] == "VULNERABILITY EXPOSURE" and t["severity"] in ("HIGH", "CRITICAL"): kind = "HIGH_PRIORITY_VULNERABILITY"
    if not kind: return None
    return {"threat_id": t["threat_id"], "timestamp": t["timestamp"], "alert_type": kind, "severity": t["severity"],
            "risk_score": t["risk_score"], "confidence_score": t["confidence_score"], "status": "NEW",
            "indicator_value": t["indicator_value"], "observation_count": t["observation_count"],
            "description": f"{kind.replace('_', ' ').title()}: {t['threat_name']}. An alert is a lead to investigate, not a confirmed incident."}

def correlate_alerts(alerts):
    """Anti alert-fatigue: same indicator + alert type -> ONE alert with summed observation_count."""
    m = {}
    for a in alerts:
        k = (a["indicator_value"], a["alert_type"])
        if k not in m: m[k] = dict(a)
        else:
            m[k]["observation_count"] += a["observation_count"]
            if a["risk_score"] > m[k]["risk_score"]:
                m[k].update(risk_score=a["risk_score"], severity=a["severity"], threat_id=a["threat_id"])
    return list(m.values())
