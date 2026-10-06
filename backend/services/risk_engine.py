"""Risk, confidence, source reliability and vulnerability priority.
RISK = how concerning. CONFIDENCE = how much we trust the evidence. They are separate on purpose.
High risk does NOT mean confirmed compromise."""
WEIGHTS = {"severity": .30, "confidence": .25, "recency": .15, "frequency": .10, "reliability": .10, "context": .10}
SEV_SCORE = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}
RELIABILITY = {"A": 100, "B": 75, "C": 50, "D": 25}   # A Highly, B Usually, C Fairly, D Unknown
SOURCES = {"Internal SOC": "A", "Security Vendor": "A", "Research Report": "B",
           "Public Threat Feed": "C", "Community Submission": "C", "Unknown Source": "D"}

def classify(score):
    return ("INFORMATIONAL" if score <= 20 else "LOW" if score <= 40 else "MEDIUM" if score <= 60
            else "HIGH" if score <= 80 else "CRITICAL")

def calculate_threat_risk(severity, confidence, days_since_seen, observations, reliability, related_count):
    f = {"severity": SEV_SCORE.get(severity, 10), "confidence": confidence,
         "recency": max(0, 100 - days_since_seen * 100 / 90),   # fades to 0 after 90 days
         "frequency": min(100, observations * 10),
         "reliability": RELIABILITY.get(reliability, 25),
         "context": min(100, related_count * 25)}
    return round(max(0, min(100, sum(WEIGHTS[k] * f[k] for k in WEIGHTS))))

def calculate_confidence(reliability, corroborating_sources, age_days):
    """0-100: source reliability + independent corroboration, minus staleness."""
    s = RELIABILITY.get(reliability, 25) * .5 + min(corroborating_sources, 4) * 12 - min(age_days, 180) * .1
    return round(max(0, min(100, s)))

def interpret(risk, confidence):
    if risk >= 61 and confidence < 40: return "Potentially serious, but evidence quality is weak - validate first."
    if risk >= 61: return "High-confidence intelligence with meaningful risk - prioritize triage."
    if confidence >= 60: return "Reliable intelligence, lower risk - monitor."
    return "Low priority - monitor or close."

def calculate_vulnerability_priority(cvss, asset_criticality, exposure, known_exploited, patch_available=True):
    """CVSS alone is not enough: add asset criticality (0-100), exposure and exploitation evidence."""
    exp = {"internet": 100, "internal": 50, "isolated": 10}.get(exposure, 50)
    s = cvss * 10 * .35 + asset_criticality * .25 + exp * .25 + (100 if known_exploited else 0) * .15
    return round(min(100, s + (0 if patch_available else 5)))
