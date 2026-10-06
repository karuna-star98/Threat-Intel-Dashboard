"""IOC validation: checks SYNTAX only, never reachability or maliciousness. Never connects to anything."""
import re, ipaddress
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
HASHES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}

def validate_indicator(value):
    v = (value or "").strip()
    r = {"valid": False, "indicator_type": None, "normalized_value": v,
         "validation_notes": "Syntactic check only - says nothing about maliciousness."}
    if not v:
        r["validation_notes"] = "Empty value."; return r
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", v, re.I):
        return {**r, "valid": True, "indicator_type": "CVE_ID", "normalized_value": v.upper()}
    try:
        ip = ipaddress.ip_address(v)
        return {**r, "valid": True, "indicator_type": "IP_ADDRESS", "normalized_value": str(ip),
                "validation_notes": f"Valid IPv{ip.version} format. Syntax check only."}
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in HASHES:
        return {**r, "valid": True, "indicator_type": "FILE_HASH", "normalized_value": v.lower(),
                "validation_notes": f"{HASHES[len(v)]}-format hash. Never execute files based on hashes."}
    if "://" in v:
        p = urlparse(v)
        if p.scheme in ("http", "https") and p.hostname and DOMAIN_RE.match(p.hostname.lower()):
            return {**r, "valid": True, "indicator_type": "URL", "normalized_value": v,
                    "validation_notes": "Valid URL format. DO NOT visit it."}
        r["validation_notes"] = "Invalid URL (needs http/https and a valid host)."; return r
    m = re.fullmatch(r"[^@\s]+@(.+)", v)
    if m and DOMAIN_RE.match(m.group(1).lower()):
        return {**r, "valid": True, "indicator_type": "EMAIL_DOMAIN", "normalized_value": m.group(1).lower(),
                "validation_notes": "Sender domain extracted from email address."}
    d = v.lower().rstrip(".")
    if DOMAIN_RE.match(d):
        return {**r, "valid": True, "indicator_type": "DOMAIN", "normalized_value": d}
    r["validation_notes"] = "Not a recognized indicator format."
    return r
