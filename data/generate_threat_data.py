"""Generates SYNTHETIC / DEMO ONLY data. RFC 5737 IPs, example.* / .invalid domains, random fake hashes."""
import csv, random, hashlib, sys, pathlib
from datetime import datetime, timedelta
ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
from services.risk_engine import calculate_threat_risk, classify, SOURCES, calculate_vulnerability_priority

rng = random.Random(42)
NOW = datetime(2026, 9, 30, 12, 0)
SEVS = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CATS = {
 "PHISHING": (["Credential Phishing Wave", "Fake Invoice Lure", "QR Lure Cluster"], ["DOMAIN", "URL", "EMAIL_DOMAIN", "IP_ADDRESS"], ("Initial Access", "Phishing", "T1566")),
 "MALWARE": (["Loader Activity", "Trojan Beaconing"], ["FILE_HASH", "IP_ADDRESS", "DOMAIN"], ("Command and Control", "Application Layer Protocol", "T1071")),
 "RANSOMWARE": (["Ransomware Precursor Activity"], ["FILE_HASH", "IP_ADDRESS", "DOMAIN"], ("Impact", "Data Encrypted for Impact", "T1486")),
 "CREDENTIAL THREATS": (["Credential Stuffing Attempts"], ["IP_ADDRESS", "EMAIL_DOMAIN"], ("Credential Access", "Brute Force", "T1110")),
 "WEB THREATS": (["Suspicious Redirect Chain"], ["URL", "DOMAIN"], ("Initial Access", "Exploit Public-Facing Application", "T1190")),
 "NETWORK THREATS": (["Suspicious Scanning Source"], ["IP_ADDRESS"], ("Discovery", "Network Service Discovery", "T1046")),
 "VULNERABILITY EXPOSURE": (["Vulnerable Service Advisory"], ["CVE_ID"], None),
 "SOCIAL ENGINEERING": (["Executive Impersonation Attempt"], ["EMAIL_DOMAIN", "DOMAIN"], ("Initial Access", "Phishing", "T1566")),
 "DATA EXPOSURE": (["Exposed Data Store Report"], ["URL", "DOMAIN"], ("Exfiltration", "Exfiltration Over Web Service", "T1567")),
 "ACCOUNT SECURITY": (["Suspicious Login Pattern"], ["IP_ADDRESS", "EMAIL_DOMAIN"], ("Initial Access", "Valid Accounts", "T1078")),
}
WORDS = ["login", "secure", "update", "portal", "billing", "verify", "account", "cloud", "files", "mail", "support", "track"]
REGIONS = ["Region-A", "Region-B", "Region-C", "Region-D", ""]
STATUS = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]

def make_ind(t, n):
    if t == "IP_ADDRESS": return f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(1, 254)}"
    if t == "DOMAIN": return f"{rng.choice(WORDS)}-{n}.{rng.choice(['example.com', 'example.org', 'example.net', 'invalid'])}"
    if t == "URL": return f"https://{rng.choice(WORDS)}-{n}.example.com/{rng.choice(WORDS)}/{n}"
    if t == "FILE_HASH": return hashlib.sha256(f"synthetic-{n}-{rng.random()}".encode()).hexdigest()
    if t == "EMAIL_DOMAIN": return f"mail-{rng.choice(WORDS)}{n}.example.org"
    return f"CVE-2099-{1000 + n % 60}"   # 2099 = clearly synthetic

def build_vulns(n=60):
    prods = ["Web Browser", "VPN Appliance", "Mail Server", "Database", "Operating System", "Firmware", "CMS Plugin"]
    rows = []
    for i in range(n):
        cvss = round(rng.uniform(3, 10), 1)
        crit, exp = rng.choice([20, 50, 80, 100]), rng.choice(["internet", "internal", "isolated"])
        ex = rng.random() < .2
        rows.append({"cve_id": f"CVE-2099-{1000 + i}", "product_category": rng.choice(prods), "severity": classify(cvss * 10),
                     "cvss_score": cvss, "published_date": (NOW - timedelta(days=rng.randint(1, 300))).date().isoformat(),
                     "patch_available": rng.choice([1, 1, 0]), "exploitation_status_demo": "EXPLOITED_DEMO" if ex else "NONE_KNOWN",
                     "asset_criticality": crit, "exposure": exp,
                     "priority_score": calculate_vulnerability_priority(cvss, crit, exp, ex),
                     "description": "SYNTHETIC / DEMO ONLY vulnerability record for awareness training."})
    return rows

def main(n=2000):
    pools = {}
    for ci, (c, (names, types, _)) in enumerate(CATS.items()):
        pools[c] = []
        for i in range(70):
            t = rng.choice(types)
            pools[c].append({"type": t, "value": make_ind(t, i + 100 * ci), "campaign": f"CMP-{c[:3]}-{i // 4:02d}",
                             "src": rng.choice(list(SOURCES)), "conf": rng.randint(20, 98)})
    rows = []
    def add(i, c, name, ind, ts, conf, src, sev_in, obs, related, status):
        rel = SOURCES[src]
        first = ts - timedelta(days=rng.randint(0, 40))
        risk = calculate_threat_risk(sev_in, conf, (NOW - ts).days, obs, rel, related)
        m = CATS[c][2] if (CATS[c][2] and conf >= 50) else None   # ATT&CK mapping only with enough confidence/context
        rows.append({"threat_id": f"THR-2026-{i:03d}", "timestamp": ts.isoformat(timespec="seconds"), "threat_name": name,
            "threat_category": c, "indicator_type": ind["type"], "indicator_value": ind["value"], "source_name": src,
            "source_reliability": rel, "confidence_score": conf, "severity": classify(risk), "risk_score": risk, "status": status,
            "first_seen": first.date().isoformat(), "last_seen": ts.date().isoformat(), "country_or_region": rng.choice(REGIONS),
            "description": "SYNTHETIC / DEMO ONLY. Observed in synthetic telemetry; requires analyst validation.",
            "mitre_tactic": m[0] if m else "", "mitre_technique": m[1] if m else "", "mitre_technique_id": m[2] if m else "",
            "cve_id": ind["value"] if ind["type"] == "CVE_ID" else "", "observation_count": obs, "campaign_id": ind["campaign"],
            "synthetic_label": "SYNTHETIC / DEMO ONLY"})
    # Demo scenario from the brief
    add(1, "PHISHING", "Synthetic Credential Phishing Campaign", {"type": "DOMAIN", "value": "login-check.invalid", "campaign": "CMP-DEMO-001"},
        NOW - timedelta(days=5), 85, "Internal SOC", "HIGH", 8, 2, "MONITORING")
    rows[0].update(risk_score=78, severity="HIGH", description="SYNTHETIC / DEMO ONLY. Indicator appears in multiple synthetic phishing observations.")
    add(2, "PHISHING", "Synthetic Credential Phishing Campaign", {"type": "IP_ADDRESS", "value": "198.51.100.25", "campaign": "CMP-DEMO-001"},
        NOW - timedelta(days=4), 80, "Security Vendor", "HIGH", 6, 2, "MONITORING")
    for i in range(3, n + 1):
        c = rng.choice(list(CATS)); ind = rng.choice(pools[c])
        ts = NOW - timedelta(days=rng.randint(0, 180), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
        conf = max(5, min(99, ind["conf"] + rng.randint(-10, 10)))
        add(i, c, rng.choice(CATS[c][0]), ind, ts, conf, ind["src"], rng.choices(SEVS, [5, 20, 35, 28, 12])[0],
            rng.randint(1, 15), rng.randint(0, 4), rng.choices(STATUS, [25, 25, 20, 20, 10])[0])
    for name, data in (("threat_intelligence_dataset.csv", rows), ("vulnerabilities.csv", build_vulns())):
        with open(ROOT / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0])); w.writeheader(); w.writerows(data)
    print(f"Wrote {len(rows)} threat records and 60 vulnerabilities (SYNTHETIC / DEMO ONLY)")

if __name__ == "__main__":
    main()
