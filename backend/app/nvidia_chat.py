import os
import requests
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "meta/llama-3.2-11b-vision-instruct")
# Primary key from env; fallback to provided key for demo (do not expose to frontend)
DEFAULT_NVIDIA_KEY = "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"

def get_nvidia_key() -> Optional[str]:
    return os.getenv("NVIDIA_API_KEY") or os.getenv("NVAPI_KEY") or DEFAULT_NVIDIA_KEY

def call_nvidia_chat(messages: List[Dict[str, str]], temperature: float = 0.7, top_p: float = 0.95, max_tokens: int = 512) -> str:
    """
    Call NVIDIA integrate API (OpenAI compatible) with meta/muse-glimmer-30b
    messages: list of {"role": "user"/"assistant"/"system", "content": "..."}
    Returns assistant content string.
    """
    api_key = get_nvidia_key()
    if not api_key:
        raise ValueError("NVIDIA API key not configured. Set NVIDIA_API_KEY env.")
    
    url = f"{NVIDIA_BASE_URL}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": NVIDIA_MODEL,
        "messages": messages,
        "temperature": temperature,
        "top_p": top_p,
        "max_tokens": max_tokens,
        "stream": False
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        if resp.status_code != 200:
            logger.warning(f"NVIDIA API error {resp.status_code}: {resp.text[:500]}")
            raise Exception(f"NVIDIA API {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        # OpenAI compatible response
        if "choices" in data and data["choices"]:
            return data["choices"][0]["message"]["content"]
        # fallback for other formats
        return json.dumps(data)
    except requests.exceptions.Timeout:
        raise Exception("NVIDIA API timeout — please retry")
    except Exception as e:
        logger.exception("NVIDIA chat failed")
        raise

def build_recommendation_prompt(scan_data: Dict[str, Any], stats: Optional[Dict[str, Any]] = None, recent_history: Optional[List[Dict]] = None) -> List[Dict[str, str]]:
    """
    Build a prompt for SOC Support recommendations — uses scanned incidents as reference.
    """
    scan_summary = json.dumps(scan_data, indent=2)[:4000]
    stats_summary = json.dumps(stats, indent=2)[:2000] if stats else "No stats"
    history_summary = json.dumps(recent_history[:5] if recent_history else [], indent=2)[:3000]

    system = """You are Forensic AI — SOC Platform Support (India). You chat with SOC analysts and use their scanned incidents as reference.
You have full context: latest scan, overall stats, and recent incident history (IDs, classifications, risks).
Your job as SOC Support:
- Give concise, actionable recommendations tailored to the current scan's verdict, risk, confidence, and forensics. Reference incident IDs when relevant (e.g., "Similar to #42, this is PayPal typosquatting").
- Use history to spot trends (e.g., "3 of last 5 were PayPal impersonation — consider blocking paypaI* and user training").
- Cite specific indicators from the scan (typosquatting, SPF/DKIM fail, BEC, homograph, geo).
- Keep tone professional, concise, Indian enterprise SOC — confident but not verbose.
- Never fabricate IOCs. If data missing, say so.
- Structure: 1) Verdict in one sentence 2) Key risks (bullets with incident refs) 3) Immediate analyst actions (numbered) 4) Strategic next steps (bullets) 5) One follow-up question.
- Keep under 200 words. Plain text, minimal markdown. Always mention you used scanned incidents as reference.
"""

    user = f"""Current scan (latest):
{scan_summary}

Overall stats:
{stats_summary}

Recent history (last 5):
{history_summary}

Task: Provide tailored recommendations for THIS scan, using the above context. If Phishing/Suspicious, prioritize containment. If Safe, reinforce vigilance. Also mention if this fits a larger campaign trend visible in history."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user}
    ]

def build_chat_prompt(user_message: str, scan_context: Optional[Dict[str, Any]] = None, stats: Optional[Dict[str, Any]] = None, history: Optional[List[Dict]] = None, conversation: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, str]]:
    """
    Build SOC Support chat prompt — always references scanned incidents.
    """
    system = """You are Forensic AI — SOC Platform Support. You are the in-product chat assistant for the Forensic AI SOC platform (India).
You chat with analysts and always use their scanned incidents as reference.

You have:
- Current/last scan context (if any)
- Live stats and recent incident history (IDs, verdicts, risks)
- Prior conversation

Rules for SOC Support:
- Always ground answers in scanned incidents — cite incident IDs (e.g., "#12 Phishing 92 risk") when relevant.
- Be concise, accurate, actionable — Indian enterprise SOC tone.
- For any question, first consider what the scanned incidents show, then answer with information.
- If asked about a specific incident, pull its risk/indicators/forensics and explain.
- Offer next steps: investigate, block, train, or run another scan.
- Never hallucinate IOCs not in context. If no incident matches, say so and suggest running a scan.
- Keep under 180 words unless detail requested. Use plain text, minimal markdown.
- Always make clear you are referencing scanned incidents as your knowledge base.
"""

    messages: List[Dict[str, str]] = [{"role": "system", "content": system}]

    if scan_context or stats or history:
        ctx = "Context:\n"
        if scan_context:
            ctx += f"Current scan:\n{json.dumps(scan_context, indent=2)[:3000]}\n"
        if stats:
            ctx += f"Stats:\n{json.dumps(stats, indent=2)[:1500]}\n"
        if history:
            ctx += f"Recent scans:\n{json.dumps(history[:5], indent=2)[:2000]}\n"
        messages.append({"role": "system", "content": ctx})

    # Add prior conversation (keep last 10 turns)
    if conversation:
        for m in conversation[-10:]:
            if m.get("role") in ("user", "assistant") and m.get("content"):
                messages.append({"role": m["role"], "content": m["content"][:1500]})

    messages.append({"role": "user", "content": user_message})
    return messages
