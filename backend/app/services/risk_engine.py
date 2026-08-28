"""
Configurable Explainable Risk Scoring Engine
Does not replace existing scoring, augments with audit trail.
"""

from typing import Dict, List, Any

DEFAULT_WEIGHTS = {
    "spf_fail": 15,
    "dkim_fail": 10,
    "dmarc_fail": 15,
    "suspicious_url": 20,
    "domain_anomaly": 10,
    "ip_reputation": 10,
    "lookalike_domain": 10,
    "urgency_language": 5,
    "attachment_anomaly": 5,
    "header_spoof": 15,
    "geo_discrepancy": 12,
    "bec_pattern": 25,
}

def compute_explainable_score(context: Dict[str, Any], weights: Dict[str, int] = None) -> Dict[str, Any]:
    if weights is None:
        weights = DEFAULT_WEIGHTS
    indicators = []
    score = 0.0

    def add(key, condition, reason):
        nonlocal score
        if condition:
            w = float(weights.get(key, 0))
            score += w
            indicators.append({"key": key, "weight": w, "reason": reason})

    auth = context.get("email_auth", {})
    add("spf_fail", auth.get("spf", "").lower() == "fail", "SPF failed")
    add("dkim_fail", auth.get("dkim", "").lower() == "fail", "DKIM failed")
    add("dmarc_fail", auth.get("dmarc", "").lower() == "fail", "DMARC failed")

    url_forensics = context.get("url_forensics", {})
    add("suspicious_url", url_forensics.get("is_homograph") or url_forensics.get("typosquatting_target"), "Suspicious URL detected")
    add("lookalike_domain", url_forensics.get("typosquatting_target"), f"Typosquatting target {url_forensics.get('typosquatting_target')}")
    add("domain_anomaly", url_forensics.get("is_homograph"), "Homograph IDN attack")

    forensics = context.get("forensics", {})
    header = forensics.get("header_forensics", {}) if isinstance(forensics, dict) else {}
    add("header_spoof", header.get("return_path_mismatch") or header.get("display_name_spoofed"), "Header spoofing detected")
    add("geo_discrepancy", forensics.get("geo_discrepancy", False), "Geographic discrepancy")

    bec = context.get("bec", {})
    add("bec_pattern", bec.get("is_bec_threat"), f"BEC threat {bec.get('bec_type')}")

    # ML indicators
    ml_indicators = context.get("ml_indicators", {})
    add("urgency_language", ml_indicators.get("urgent_language"), "Urgency language detected")

    # Clamp
    score = max(0.0, min(100.0, score))
    severity = "LOW"
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"

    return {
        "score": round(score, 1),
        "severity": severity,
        "indicators": indicators,
        "weights_used": weights
    }
