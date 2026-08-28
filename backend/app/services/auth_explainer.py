"""
SPF/DKIM/DMARC explanation module
Provides human-readable explanations without inventing evidence.
"""

from typing import Dict, Any

def explain_spf(spf_result: str, domain: str, sender_ip: str) -> Dict[str, Any]:
    spf_result = (spf_result or "None").lower()
    if spf_result == "pass":
        return {"result": "PASS", "explanation": f"SPF passed for domain {domain}. Sending IP {sender_ip} is authorized."}
    elif spf_result == "fail":
        return {"result": "FAIL", "explanation": f"SPF failed for domain {domain}. Sending IP {sender_ip} is NOT authorized by SPF record."}
    elif spf_result == "softfail":
        return {"result": "SOFTFAIL", "explanation": f"SPF softfail for domain {domain}. IP {sender_ip} is not explicitly authorized."}
    elif spf_result == "neutral":
        return {"result": "NEUTRAL", "explanation": f"SPF neutral for domain {domain}. No SPF policy applies."}
    else:
        return {"result": "NONE", "explanation": f"SPF check not performed or no SPF record for {domain}."}

def explain_dkim(dkim_result: str, signing_domain: str) -> Dict[str, Any]:
    dkim_result = (dkim_result or "None").lower()
    if dkim_result == "pass":
        return {"result": "PASS", "explanation": f"DKIM signature verified for signing domain {signing_domain}."}
    elif dkim_result == "fail":
        return {"result": "FAIL", "explanation": f"DKIM verification failed for signing domain {signing_domain}. Signature invalid or missing."}
    else:
        return {"result": "NONE", "explanation": f"DKIM check not performed or no DKIM signature present."}

def explain_dmarc(dmarc_result: str, spf_result: str, dkim_result: str, alignment: bool) -> Dict[str, Any]:
    dmarc_result = (dmarc_result or "None").lower()
    if dmarc_result == "pass":
        return {"result": "PASS", "explanation": "DMARC passed. SPF and/or DKIM aligned with From domain."}
    elif dmarc_result == "fail":
        reasons = []
        if spf_result.lower() != "pass":
            reasons.append("SPF failure")
        if dkim_result.lower() != "pass":
            reasons.append("DKIM failure")
        if not alignment:
            reasons.append("domain alignment failed")
        reason_str = ", ".join(reasons) if reasons else "policy violation"
        return {"result": "FAIL", "explanation": f"DMARC failed because {reason_str}."}
    else:
        return {"result": "NONE", "explanation": "DMARC check not performed or no DMARC policy."}
