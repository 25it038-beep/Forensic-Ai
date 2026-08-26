import json
import os
import re
import datetime
import asyncio
import logging
import csv
import io
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, HTMLResponse
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from sqlalchemy import func
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False
    class RateLimitExceeded(Exception):
        pass
    def _rate_limit_exceeded_handler(request, exc):
        raise exc
    def get_remote_address(request):
        return request.client.host if request.client else "unknown"
    class Limiter:
        def __init__(self, key_func=None):
            self.key_func = key_func
        def limit(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

from .database import engine, Base, get_db, migrate_db
from .models import User, ScanHistory
from .schemas import (
    EmailPredictRequest, PredictResponse, StatsResponse,
    UrlAnalyzeRequest, UrlAnalyzeResponse,
    VirusTotalResult, WhoisResult, DnsResult, SslResult, EmailAuthResult, AttachmentInfo, LlmAnalysisResult,
    GeoLocationResult, EmailHop, HeaderForensics, AttachmentForensics, UrlForensics, DigitalForensicsResult,
    BecAnalysisResult, AttributionIntelligence, CorrelationGraph
)
from .classifier import PhishingClassifier
from .utils import (
    check_virustotal, get_whois_info, get_dns_info, get_ssl_info, check_url_reputation,
    get_extension_zip_bytes, sanitize_html,
    analyze_attachment_forensics, analyze_url_forensics,
    universal_file_inspector, analyze_bec_patterns, analyze_attribution_and_infrastructure, build_correlation_graph,
    resolve_universal_geolocation, resolve_sender_identity_geolocation
)
from .llm import generate_llm_explanation, generate_url_llm_explanation
from .auth import hash_password, verify_password, create_access_token, get_optional_current_user, get_current_user
from .schemas import UserRegister, UserLogin, UserResponse, Token
from .nvidia_chat import call_nvidia_chat, build_chat_prompt, build_recommendation_prompt

def _model_dump(obj):
    if obj is None:
        return {}
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return dict(obj)

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        migrate_db()
        logger.info("Database migrated successfully")
    except Exception as e:
        logger.warning("Database migration failed on startup: %s", e)
    yield

app = FastAPI(
    title="AI-Powered Phishing Email Detector Enterprise API",
    description="SaaS Backend API for detecting phishing emails, URLs, and attachments using ML and Threat Intelligence",
    version="2.0.0",
    lifespan=lifespan
)

# ---- CORS: production-safe ----
raw_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,https://*.vercel.app,https://*.onrender.com,https://*.netlify.app")
ALLOWED_ORIGINS: List[str] = []
ALLOWED_ORIGIN_REGEXES: List[str] = []

def _wildcard_to_regex(pattern: str) -> str:
    # Convert https://*.vercel.app -> https://([a-z0-9-]+\.)*vercel\.app
    escaped = re.escape(pattern).replace(r"\*", "([a-z0-9-]+\\.)*").replace(r"\(\[a-z0-9-\]\+\.\\\)\*", r"([a-z0-9-]+\.)*")
    # simpler: handle *. case
    if "*." in pattern:
        base = pattern.replace("https://*.", "").replace("http://*.", "")
        base_escaped = re.escape(base)
        return rf"https://([a-z0-9-]+\.)*{base_escaped}"
    return escaped

for raw_origin in raw_cors_origins.split(","):
    origin = raw_origin.strip().rstrip("/")
    if not origin:
        continue
    if origin == "*":
        ALLOWED_ORIGIN_REGEXES.append(r".*")
    elif "*." in origin:
        ALLOWED_ORIGIN_REGEXES.append(_wildcard_to_regex(origin))
        # also allow exact root domain without subdomain
        root = origin.replace("*.", "")
        ALLOWED_ORIGINS.append(root)
    else:
        ALLOWED_ORIGINS.append(origin)

# Explicitly ensure localhost allowed
for local in ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:8000"]:
    if local not in ALLOWED_ORIGINS:
        ALLOWED_ORIGINS.append(local)

# Allow browser extensions (chrome-extension://, moz-extension://)
ALLOWED_ORIGIN_REGEXES.append(r"chrome-extension://.*")
# Local preview / dev hosts (any port) + cloudflare preview tunnels
ALLOWED_ORIGIN_REGEXES.append(r"http://localhost:\d+")
ALLOWED_ORIGIN_REGEXES.append(r"http://127\.0\.0\.1:\d+")
ALLOWED_ORIGIN_REGEXES.append(r"https://.*\.trycloudflare\.com")
ALLOWED_ORIGIN_REGEXES.append(r"https://.*\.preview\..*")
ALLOWED_ORIGIN_REGEXES.append(r"https://.*\.loca\.lt")
ALLOWED_ORIGIN_REGEXES.append(r"https://.*\.ngrok.*")
# In non-production, allow any https preview (Render/Vercel preview deploys)
if os.getenv("ENV", os.getenv("NODE_ENV", "development")) != "production":
    ALLOWED_ORIGIN_REGEXES.append(r"https://.*")
    # also allow http for local network testing
    ALLOWED_ORIGIN_REGEXES.append(r"http://.*")

app.state.limiter = limiter
if SLOWAPI_AVAILABLE:
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex="|".join(ALLOWED_ORIGIN_REGEXES) if ALLOWED_ORIGIN_REGEXES else None,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Minimal CSP that does not break SPA; allow self + fonts + data images + api host
    # Do not inject dynamic origin to avoid CSP bypass
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https: http://localhost:* http://127.0.0.1:*;"
    )
    return response

classifier = PhishingClassifier()
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(10 * 1024 * 1024)))

# Backward compat shim for optional auth without JWT when Authorization absent
# get_optional_current_user is imported from auth; keep alias for legacy imports if any


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL. Use http:// or https://")
    return url

def validate_email_text(text: str) -> str:
    sanitized_text = sanitize_html(text)
    if not sanitized_text or len(sanitized_text.strip()) < 3:
        raise HTTPException(status_code=400, detail="Invalid or empty email text.")
    return sanitized_text

@app.get("/")
def root_endpoint() -> Dict[str, Any]:
    return {"status": "online", "service": "Forensic AI Engine", "version": "3.0", "docs": "/docs", "health": "/health"}

@app.get("/api")
def api_root() -> Dict[str, str]:
    return {"status": "healthy", "service": "forensic-ai-api", "version": "3.0"}

@app.get("/health")
@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "forensic-ai"}

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# --- Auth Routes (missing feature) ---
@app.post("/api/auth/register", response_model=UserResponse)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=payload.email.lower().strip(), hashed_password=hash_password(payload.password), role="user")
    db.add(user); db.commit(); db.refresh(user)
    logger.info("New user registered: %s", user.email)
    return user

@app.post("/api/auth/login", response_model=Token)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    token = create_access_token({"sub": user.email, "uid": user.id, "role": user.role})
    return Token(access_token=token, token_type="bearer", user=user)

@app.get("/api/auth/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user

# --- Core Scanner Routes ---

@app.post("/api/predict", response_model=PredictResponse)
@limiter.limit("30/minute")
async def predict_email(
    request: Request,
    payload: EmailPredictRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    sanitized_text = validate_email_text(payload.text)
    result = await run_in_threadpool(classifier.predict, sanitized_text)
    raw_source = payload.text
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', raw_source)
    vt_result = None
    whois_result = None
    domain = None
    url_forensics_res = None
    forensic_flags: List[str] = []
    sender_match = re.search(r'From:\s*([^\r\n]+)', raw_source, re.IGNORECASE)
    detected_sender = sender_match.group(1).strip() if sender_match else "Unknown Sender"
    if "<" in detected_sender and ">" in detected_sender:
        try:
            detected_sender = detected_sender.split("<")[0].strip().strip('"\'') + " <" + detected_sender.split("<")[1].split(">")[0] + ">"
        except Exception:
            pass
    subj_match = re.search(r'Subject:\s*([^\r\n]+)', raw_source, re.IGNORECASE)
    detected_subject = subj_match.group(1).strip() if subj_match else "Raw Text / Email Stream"
    url_forensics_dict = None
    if urls:
        first_url = urls[0]
        domain = re.sub(r'^https?://', '', first_url).split('/')[0].split(':')[0].lower()
    elif "@" in detected_sender:
        domain = detected_sender.split("@")[-1].replace(">", "").strip().lower()
        first_url = f"https://{domain}" if domain else ""
    else:
        first_url = ""

    if domain:
        vt_result_dict, whois_result_dict, url_forensics_dict = await asyncio.gather(
            run_in_threadpool(check_virustotal, first_url or f"https://{domain}"),
            run_in_threadpool(get_whois_info, domain),
            run_in_threadpool(analyze_url_forensics, first_url or f"https://{domain}", domain)
        )
        if vt_result_dict:
            vt_result = VirusTotalResult(**vt_result_dict)
        if whois_result_dict:
            whois_result = WhoisResult(**whois_result_dict)
        if url_forensics_dict:
            url_forensics_res = UrlForensics(**url_forensics_dict)
            if url_forensics_res.is_homograph:
                forensic_flags.append(f"IDN Homograph Deception: Target domain '{domain}' uses deceptive script characters ({url_forensics_res.punycode}).")
                result["risk_score"] = max(result["risk_score"], 85.0)
                result["classification"] = "Phishing"
            elif url_forensics_res.typosquatting_target:
                forensic_flags.append(f"Typosquatting: Domain '{domain}' is 1 character distance from trusted brand '{url_forensics_res.typosquatting_target}'.")
                result["risk_score"] = max(result["risk_score"], 75.0)
                if result["classification"] == "Safe":
                    result["classification"] = "Suspicious"
    origin_geo_dict, sender_geo_dict, hops_list, parsed_hf = await run_in_threadpool(
        resolve_universal_geolocation,
        raw_source, detected_sender, domain or "", None, url_forensics_dict
    )
    origin_geo = GeoLocationResult(**origin_geo_dict) if origin_geo_dict else None
    sender_geo = GeoLocationResult(**sender_geo_dict) if sender_geo_dict else None
    if sender_geo and origin_geo and sender_geo.country_code != origin_geo.country_code:
        if sender_geo.country not in ["Unknown", "Private Network"] and origin_geo.country not in ["Unknown", "Private Network"]:
            forensic_flags.append(
                f"Geographic Discrepancy: Sender identity claims {sender_geo.country} ({sender_geo.city}), but mail server transmitted from {origin_geo.country} ({origin_geo.city}). Possible spoofing."
            )
    header_forensics = None
    if parsed_hf:
        header_forensics = HeaderForensics(**parsed_hf)
    elif hops_list:
        header_forensics = HeaderForensics(
            originating_ip=origin_geo.ip if origin_geo else None,
            originating_geo=origin_geo,
            hops=[EmailHop(**h) for h in hops_list],
            return_path=None, reply_to=None,
            from_header=detected_sender if detected_sender != "Unknown Sender" else None,
            message_id=None, mailer="Standard User-Agent",
            return_path_mismatch=False, display_name_spoofed=False, suspicious_mailer=False
        )
    bec_data = analyze_bec_patterns(sanitized_text, detected_subject, detected_sender)
    bec_res = BecAnalysisResult(**bec_data)
    if bec_res.is_bec_threat:
        forensic_flags.append(f"BEC Threat Vector: {bec_res.bec_type} ({bec_res.urgency_level} urgency).")
        result["risk_score"] = min(result["risk_score"] + 25.0, 100.0)
        result["classification"] = "Phishing"
    attrib_data = analyze_attribution_and_infrastructure(
        _model_dump(header_forensics) if header_forensics else None,
        _model_dump(origin_geo) if origin_geo else None,
        _model_dump(whois_result) if whois_result else None,
        domain, detected_sender, result["risk_score"]
    )
    attrib_res = AttributionIntelligence(**attrib_data)
    for ind in attrib_res.threat_actor_indicators:
        forensic_flags.append(ind)
    target_brand = url_forensics_res.typosquatting_target if url_forensics_res else None
    graph_data = build_correlation_graph(
        detected_sender, domain, _model_dump(origin_geo) if origin_geo else None,
        _model_dump(header_forensics) if header_forensics else None, [], target_brand, attrib_res.suspected_campaign, result["risk_score"]
    )
    graph_res = CorrelationGraph(**graph_data)
    llm_res_dict = await run_in_threadpool(generate_llm_explanation, sanitized_text, result["classification"], result["detected_indicators"])
    llm_analysis = LlmAnalysisResult(**llm_res_dict)
    forensics_obj = DigitalForensicsResult(
        header_forensics=header_forensics, attachment_forensics=[], url_forensics=url_forensics_res,
        origin_geolocation=origin_geo, sender_geolocation=sender_geo,
        forensic_risk_score=round(result["risk_score"], 1), forensic_flags=forensic_flags,
        bec_analysis=bec_res, attribution=attrib_res, correlation_graph=graph_res
    )
    db_history = ScanHistory(
        user_id=current_user.id if current_user else None,
        subject=detected_subject, sender=detected_sender, body_preview=sanitized_text[:200],
        classification=result["classification"], confidence_score=result["confidence_score"], risk_score=result["risk_score"],
        explanation=result["explanation"], detected_indicators=json.dumps(result["detected_indicators"]),
        threat_type=llm_analysis.mitre_mappings[0].name if llm_analysis.mitre_mappings else "Phishing",
        virustotal_results=json.dumps(_model_dump(vt_result)) if vt_result else None,
        whois_results=json.dumps(_model_dump(whois_result)) if whois_result else None,
        email_auth_results=json.dumps({"spf": "None", "dkim": "None", "dmarc": "None", "is_authenticated": True}),
        attachment_analysis=json.dumps([]), llm_analysis=json.dumps(_model_dump(llm_analysis)),
        domain=domain, country=origin_geo.country if origin_geo else "Unknown",
        origin_country_code=origin_geo.country_code if origin_geo else "UN",
        origin_ip=origin_geo.ip if origin_geo else None,
        geolocation_data=json.dumps(_model_dump(origin_geo)) if origin_geo else None,
        forensics_data=json.dumps(_model_dump(forensics_obj)), file_type="TXT"
    )
    db.add(db_history); db.commit(); db.refresh(db_history)
    result.update({
        "id": db_history.id, "user_id": db_history.user_id, "subject": db_history.subject, "sender": db_history.sender,
        "created_at": db_history.created_at, "threat_type": db_history.threat_type,
        "virustotal_results": vt_result, "whois_results": whois_result, "email_auth_results": EmailAuthResult(),
        "attachment_analysis": [], "llm_analysis": llm_analysis, "geolocation": origin_geo, "sender_geolocation": sender_geo, "forensics": forensics_obj
    })
    return result

@app.post("/api/upload", response_model=PredictResponse)
@limiter.limit("30/minute")
async def upload_file_or_email(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    filename = (file.filename or "uploaded_artifact").strip()
    if not filename or "/" in filename or "\\" in filename:
        filename = os.path.basename(filename)
    contents = b""
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        contents += chunk
        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File size exceeds the 10MB limit.")
    file_info = await run_in_threadpool(universal_file_inspector, filename, contents)
    subject = file_info["subject"]
    sender = file_info["sender"]
    body = sanitize_html(file_info["body"])
    file_category = file_info["file_category"]
    forensic_flags = list(file_info["forensic_flags"])
    attachment_forensics_list = [AttachmentForensics(**af) for af in file_info["attachment_forensics"]]
    header_forensics = HeaderForensics(**file_info["header_forensics"]) if file_info["header_forensics"] else None
    email_auth = EmailAuthResult(**file_info["email_auth_results"])
    ocr_text = file_info["ocr_extracted_text"]
    attachment_analysis_list = [
        AttachmentInfo(
            filename=af.filename,
            risk_level=af.risk_level,
            reason=af.details or ("Disguised executable payload" if af.is_disguised_executable else "Analyzed file artifact"),
            action="Block & Quarantine" if af.risk_level == "High" or af.is_disguised_executable else "Allow with Sandbox"
        ) for af in attachment_forensics_list
    ]
    result = await run_in_threadpool(classifier.predict, body, sender=sender, subject=subject, attachments=[af.filename for af in attachment_forensics_list])
    urls = file_info["extracted_urls"]
    vt_result = None; whois_result = None; domain = None; url_forensics_res = None; url_forensics_dict = None
    if urls:
        first_url = urls[0]
        domain = re.sub(r'^https?://', '', first_url).split('/')[0].split(':')[0].lower()
        vt_result_dict, whois_result_dict, url_forensics_dict = await asyncio.gather(
            run_in_threadpool(check_virustotal, first_url),
            run_in_threadpool(get_whois_info, domain),
            run_in_threadpool(analyze_url_forensics, first_url, domain)
        )
        vt_result = VirusTotalResult(**vt_result_dict)
        whois_result = WhoisResult(**whois_result_dict)
        url_forensics_res = UrlForensics(**url_forensics_dict)
        if url_forensics_res.is_homograph:
            forensic_flags.append("IDN Homograph Attack: Deceptive non-ASCII/mixed characters in link domain.")
            result["risk_score"] = min(result["risk_score"] + 30.0, 100.0)
            result["classification"] = "Phishing"
        if url_forensics_res.typosquatting_target:
            forensic_flags.append(f"Brand Typosquatting: Link mimics '{url_forensics_res.typosquatting_target}' (Edit Distance: {url_forensics_res.levenshtein_distance}).")
        if vt_result.malicious > 0:
            result["risk_score"] = min(result["risk_score"] + 25.0, 100.0)
            result["classification"] = "Phishing"
    if not email_auth.is_authenticated:
        result["risk_score"] = min(result["risk_score"] + 15.0, 100.0)
        if result["classification"] == "Safe":
            result["classification"] = "Suspicious"
    has_high_risk_att = any(a.risk_level == "High" for a in attachment_analysis_list)
    has_disguised_att = any(a.is_disguised_executable for a in attachment_forensics_list)
    if has_disguised_att or has_high_risk_att:
        result["risk_score"] = min(result["risk_score"] + 35.0, 100.0)
        result["classification"] = "Phishing"
    if header_forensics and (header_forensics.return_path_mismatch or header_forensics.display_name_spoofed):
        result["risk_score"] = min(result["risk_score"] + 15.0, 100.0)
        if result["classification"] == "Safe":
            result["classification"] = "Suspicious"
    origin_geo_dict, sender_geo_dict, hops_list, parsed_hf = await run_in_threadpool(
        resolve_universal_geolocation, body, sender, domain or "", _model_dump(header_forensics) if header_forensics else None, url_forensics_dict
    )
    origin_geo = GeoLocationResult(**origin_geo_dict) if origin_geo_dict else None
    sender_geo = GeoLocationResult(**sender_geo_dict) if sender_geo_dict else None
    if sender_geo and origin_geo and sender_geo.country_code != origin_geo.country_code:
        if sender_geo.country not in ["Unknown", "Private Network"] and origin_geo.country not in ["Unknown", "Private Network"]:
            forensic_flags.append(f"Geographic Discrepancy: Sender identity claims {sender_geo.country} ({sender_geo.city}), but mail server transmitted from {origin_geo.country} ({origin_geo.city}). Possible spoofing.")
    if header_forensics:
        if not header_forensics.originating_geo:
            header_forensics.originating_geo = origin_geo
        if not header_forensics.originating_ip and origin_geo:
            header_forensics.originating_ip = origin_geo.ip
        if not header_forensics.hops and hops_list:
            header_forensics.hops = [EmailHop(**h) for h in hops_list]
    elif hops_list:
        header_forensics = HeaderForensics(
            originating_ip=origin_geo.ip if origin_geo else None, originating_geo=origin_geo,
            hops=[EmailHop(**h) for h in hops_list], return_path=None, reply_to=None,
            from_header=sender if sender != "Universal Threat Inspector" else None,
            message_id=None, mailer="Standard Mail Relay", return_path_mismatch=False, display_name_spoofed=False, suspicious_mailer=False
        )
    bec_data = analyze_bec_patterns(body, subject, sender)
    bec_res = BecAnalysisResult(**bec_data)
    if bec_res.is_bec_threat:
        forensic_flags.append(f"BEC Threat Vector: {bec_res.bec_type} ({bec_res.urgency_level} urgency).")
        result["risk_score"] = min(result["risk_score"] + 25.0, 100.0)
        result["classification"] = "Phishing"
    attrib_data = analyze_attribution_and_infrastructure(
        _model_dump(header_forensics) if header_forensics else None,
        _model_dump(origin_geo) if origin_geo else None,
        _model_dump(whois_result) if whois_result else None,
        domain, sender, result["risk_score"]
    )
    attrib_res = AttributionIntelligence(**attrib_data)
    for ind in attrib_res.threat_actor_indicators:
        forensic_flags.append(ind)
    target_brand = url_forensics_res.typosquatting_target if url_forensics_res else None
    graph_data = build_correlation_graph(
        sender, domain, _model_dump(origin_geo) if origin_geo else None,
        _model_dump(header_forensics) if header_forensics else None,
        [_model_dump(af) for af in attachment_forensics_list], target_brand, attrib_res.suspected_campaign, result["risk_score"]
    )
    graph_res = CorrelationGraph(**graph_data)
    forensics_obj = DigitalForensicsResult(
        header_forensics=header_forensics, attachment_forensics=attachment_forensics_list, url_forensics=url_forensics_res,
        origin_geolocation=origin_geo, sender_geolocation=sender_geo,
        forensic_risk_score=round(result["risk_score"], 1), forensic_flags=forensic_flags,
        bec_analysis=bec_res, attribution=attrib_res, correlation_graph=graph_res
    )
    llm_res_dict = await run_in_threadpool(generate_llm_explanation, body, result["classification"], result["detected_indicators"])
    llm_analysis = LlmAnalysisResult(**llm_res_dict)
    db_history = ScanHistory(
        user_id=current_user.id if current_user else None, subject=subject, sender=sender, body_preview=body[:200],
        classification=result["classification"], confidence_score=result["confidence_score"], risk_score=result["risk_score"],
        explanation=result["explanation"], detected_indicators=json.dumps(result["detected_indicators"]),
        threat_type=llm_analysis.mitre_mappings[0].name if llm_analysis.mitre_mappings else "Phishing",
        virustotal_results=json.dumps(_model_dump(vt_result)) if vt_result else None,
        whois_results=json.dumps(_model_dump(whois_result)) if whois_result else None,
        email_auth_results=json.dumps(_model_dump(email_auth)),
        attachment_analysis=json.dumps([_model_dump(a) for a in attachment_analysis_list]),
        llm_analysis=json.dumps(_model_dump(llm_analysis)),
        domain=domain, country=origin_geo.country if origin_geo else "Unknown",
        origin_country_code=origin_geo.country_code if origin_geo else "UN",
        origin_ip=origin_geo.ip if origin_geo else None,
        geolocation_data=json.dumps(_model_dump(origin_geo)) if origin_geo else None,
        forensics_data=json.dumps(_model_dump(forensics_obj)), file_type=file_category.upper()
    )
    db.add(db_history); db.commit(); db.refresh(db_history)
    result.update({
        "id": db_history.id, "user_id": db_history.user_id, "subject": db_history.subject, "sender": db_history.sender,
        "created_at": db_history.created_at, "threat_type": db_history.threat_type,
        "virustotal_results": vt_result, "whois_results": whois_result, "email_auth_results": email_auth,
        "attachment_analysis": attachment_analysis_list, "llm_analysis": llm_analysis,
        "geolocation": origin_geo, "sender_geolocation": sender_geo, "forensics": forensics_obj,
        "ocr_extracted_text": ocr_text if ocr_text else None
    })
    return result

@app.post("/api/analyze-url", response_model=UrlAnalyzeResponse)
@limiter.limit("30/minute")
async def analyze_url_endpoint(
    request: Request, payload: UrlAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    sanitized_url = validate_url(payload.url.strip())
    result = check_url_reputation(sanitized_url)
    domain = result["domain"]
    forensic_flags: List[str] = []
    vt_result_dict, whois_result_dict, dns_result_dict, ssl_result_dict, url_forensics_dict = await asyncio.gather(
        run_in_threadpool(check_virustotal, sanitized_url),
        run_in_threadpool(get_whois_info, domain),
        run_in_threadpool(get_dns_info, domain),
        run_in_threadpool(get_ssl_info, domain),
        run_in_threadpool(analyze_url_forensics, sanitized_url, domain)
    )
    vt_result = VirusTotalResult(**vt_result_dict)
    whois_result = WhoisResult(**whois_result_dict)
    dns_result = DnsResult(**dns_result_dict)
    ssl_result = SslResult(**ssl_result_dict)
    url_forensics_res = UrlForensics(**url_forensics_dict)
    risk_score = result["risk_score"]
    if url_forensics_res.is_homograph:
        risk_score += 35.0
        result["reasons"].append(f"IDN Homograph Attack: Deceptive character set (Punycode: {url_forensics_res.punycode or 'detected'})")
        result["threat_type"] = "IDN Homograph Domain Spoofing"
        forensic_flags.append(f"IDN Homograph Domain detected ({url_forensics_res.punycode})")
    if url_forensics_res.typosquatting_target:
        risk_score += 25.0
        result["reasons"].append(f"Typosquatting: Domain mimics legitimate brand '{url_forensics_res.typosquatting_target}' (Edit distance: {url_forensics_res.levenshtein_distance})")
        forensic_flags.append(f"Brand Typosquatting impersonating '{url_forensics_res.typosquatting_target}'")
    if vt_result.malicious > 0:
        risk_score += 30.0
        result["status"] = "Dangerous"
    if whois_result.is_new_domain:
        risk_score += 15.0
    if not ssl_result.has_ssl:
        risk_score += 20.0
        if result["threat_type"] == "No Threat Detected":
            result["threat_type"] = "Insecure Connection (No SSL)"
    elif ssl_result.is_expired:
        risk_score += 15.0
        if result["threat_type"] == "No Threat Detected":
            result["threat_type"] = "Expired SSL Certificate"
    elif ssl_result.is_self_signed:
        risk_score += 10.0
        if result["threat_type"] == "No Threat Detected":
            result["threat_type"] = "Untrusted / Self-Signed SSL"
    if dns_result.ip_address == "Unknown":
        risk_score += 25.0
        result["threat_type"] = "DNS Resolution Failure"
    elif not dns_result.mx_records:
        risk_score += 5.0
    risk_score = min(max(risk_score, 0.0), 100.0)
    result["risk_score"] = risk_score
    if risk_score >= 70.0:
        result["status"] = "Dangerous"
    elif risk_score >= 30.0:
        result["status"] = "Suspicious"
    else:
        result["status"] = "Safe"
    if result["status"] == "Safe":
        result["threat_type"] = "No Threat Detected"
        result["advice"] = f"This URL appears to be clean. It is secured with a valid SSL certificate from {ssl_result.issuer}."
    else:
        if result["threat_type"] == "No Threat Detected":
            result["threat_type"] = "Suspicious URL Indicators"
        result["advice"] = f"Caution: This URL has a risk score of {risk_score:.1f}/100. "
        if ssl_result.is_expired or not ssl_result.has_ssl:
            result["advice"] += "It lacks secure SSL encryption. "
        if whois_result.is_new_domain:
            result["advice"] += "The domain is very new. "
        result["advice"] += "Avoid entering passwords or sensitive data."
    llm_analysis_dict = await run_in_threadpool(
        generate_url_llm_explanation, sanitized_url, domain, result["status"], risk_score,
        {"status": result["status"], "reasons": result["reasons"]},
        whois_result_dict, dns_result_dict, ssl_result_dict, vt_result_dict
    )
    if llm_analysis_dict.get("danger_explanation"):
        summary = llm_analysis_dict["danger_explanation"].split("\n\n")[0]
        summary = re.sub(r'^###\s+Executive\s+Summary\s*\n', '', summary)
        result["advice"] = summary
    db_class = "Phishing" if result["status"] == "Dangerous" else result["status"]
    origin_geo = url_forensics_res.geo
    sender_geo_dict = resolve_sender_identity_geolocation("", "", domain)
    sender_geo = GeoLocationResult(**sender_geo_dict) if sender_geo_dict else origin_geo
    attrib_data = analyze_attribution_and_infrastructure(
        None, _model_dump(origin_geo) if origin_geo else None, _model_dump(whois_result) if whois_result else None, domain, "URL Target", risk_score
    )
    attrib_res = AttributionIntelligence(**attrib_data)
    for ind in attrib_res.threat_actor_indicators:
        forensic_flags.append(ind)
    target_brand = url_forensics_res.typosquatting_target
    graph_data = build_correlation_graph(
        "Direct Link Access", domain, _model_dump(origin_geo) if origin_geo else None, None, [], target_brand, attrib_res.suspected_campaign, risk_score
    )
    graph_res = CorrelationGraph(**graph_data)
    forensics_obj = DigitalForensicsResult(
        header_forensics=None, attachment_forensics=[], url_forensics=url_forensics_res,
        origin_geolocation=origin_geo, forensic_risk_score=risk_score, forensic_flags=forensic_flags,
        bec_analysis=BecAnalysisResult(), attribution=attrib_res, correlation_graph=graph_res
    )
    db_history = ScanHistory(
        user_id=current_user.id if current_user else None, subject=f"URL Scan: {domain}", sender="System URL Analyzer",
        body_preview=f"URL: {result['url']}\nThreat: {result['threat_type']}\nAdvice: {result['advice']}",
        classification=db_class, confidence_score=95.0, risk_score=result["risk_score"], explanation=result["advice"],
        detected_indicators=json.dumps({
            "urgent_language": False, "suspicious_urls": result["status"] != "Safe",
            "fake_login": any(kw in domain for kw in ["login", "signin", "secure", "verify"]),
            "password_request": False, "banking_scam": any(kw in domain for kw in ["chase", "bank"]),
            "financial_fraud": False, "crypto_scam": any(kw in domain for kw in ["coinbase", "metamask"]),
            "grammar_issues": False, "spoofed_sender": False, "dangerous_attachments": False
        }),
        threat_type=result["threat_type"],
        virustotal_results=json.dumps(_model_dump(vt_result)),
        whois_results=json.dumps(_model_dump(whois_result)),
        email_auth_results=json.dumps({"spf": "None", "dkim": "None", "dmarc": "None", "is_authenticated": True}),
        attachment_analysis=json.dumps([]), llm_analysis=json.dumps(llm_analysis_dict),
        domain=domain, country=origin_geo.country if origin_geo else "Unknown",
        origin_country_code=origin_geo.country_code if origin_geo else "UN",
        origin_ip=origin_geo.ip if origin_geo else None,
        geolocation_data=json.dumps(_model_dump(origin_geo)) if origin_geo else None,
        forensics_data=json.dumps(_model_dump(forensics_obj)), file_type="URL"
    )
    db.add(db_history); db.commit(); db.refresh(db_history)
    result.update({
        "id": db_history.id, "created_at": db_history.created_at,
        "virustotal_results": vt_result, "whois_results": whois_result, "dns_results": dns_result, "ssl_results": ssl_result,
        "geolocation": origin_geo, "sender_geolocation": sender_geo if 'sender_geo' in locals() else origin_geo, "forensics": forensics_obj
    })
    return result

@app.get("/api/history", response_model=List[PredictResponse])
def get_history(limit: int = 50, skip: int = 0, db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_optional_current_user)):
    query = db.query(ScanHistory)
    if current_user and current_user.role != "admin":
        query = query.filter(ScanHistory.user_id == current_user.id)
    history_items = query.order_by(ScanHistory.created_at.desc()).offset(skip).limit(limit).all()
    response = []
    for item in history_items:
        indicators = json.loads(item.detected_indicators) if item.detected_indicators else {}
        vt = VirusTotalResult(**json.loads(item.virustotal_results)) if item.virustotal_results else None
        whois_res = WhoisResult(**json.loads(item.whois_results)) if item.whois_results else None
        email_auth = EmailAuthResult(**json.loads(item.email_auth_results)) if item.email_auth_results else EmailAuthResult()
        attachments = [AttachmentInfo(**a) for a in json.loads(item.attachment_analysis)] if item.attachment_analysis else []
        llm = LlmAnalysisResult(**json.loads(item.llm_analysis)) if item.llm_analysis else None
        geo = GeoLocationResult(**json.loads(item.geolocation_data)) if item.geolocation_data else None
        forensics_obj = DigitalForensicsResult(**json.loads(item.forensics_data)) if item.forensics_data else None
        reconstructed = classifier.predict(item.body_preview, sender=item.sender or "", subject=item.subject or "")
        response.append(PredictResponse(
            id=item.id, user_id=item.user_id, subject=item.subject, sender=item.sender,
            classification=item.classification, confidence_score=item.confidence_score, risk_score=item.risk_score,
            explanation=item.explanation, detected_indicators=indicators, highlighted_text=reconstructed["highlighted_text"],
            xai_keywords=reconstructed["xai_keywords"], created_at=item.created_at,
            threat_type=item.threat_type, virustotal_results=vt, whois_results=whois_res, email_auth_results=email_auth,
            attachment_analysis=attachments, llm_analysis=llm, geolocation=geo, forensics=forensics_obj
        ))
    return response

@app.get("/api/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_optional_current_user)):
    filter_user = ScanHistory.user_id == current_user.id if (current_user and current_user.role != "admin") else True
    total = db.query(ScanHistory).filter(filter_user).count()
    safe = db.query(ScanHistory).filter(filter_user, ScanHistory.classification == "Safe").count()
    suspicious = db.query(ScanHistory).filter(filter_user, ScanHistory.classification == "Suspicious").count()
    phishing = db.query(ScanHistory).filter(filter_user, ScanHistory.classification == "Phishing").count()
    avg_conf = 0.0
    if total > 0:
        avg_conf_query = db.query(ScanHistory).filter(filter_user).with_entities(ScanHistory.confidence_score).all()
        avg_conf = sum(c[0] for c in avg_conf_query) / total if avg_conf_query else 0.0
    distribution = {
        "0-20": db.query(ScanHistory).filter(filter_user, ScanHistory.risk_score <= 20).count(),
        "21-40": db.query(ScanHistory).filter(filter_user, (ScanHistory.risk_score > 20) & (ScanHistory.risk_score <= 40)).count(),
        "41-60": db.query(ScanHistory).filter(filter_user, (ScanHistory.risk_score > 40) & (ScanHistory.risk_score <= 60)).count(),
        "61-80": db.query(ScanHistory).filter(filter_user, (ScanHistory.risk_score > 60) & (ScanHistory.risk_score <= 80)).count(),
        "81-100": db.query(ScanHistory).filter(filter_user, ScanHistory.risk_score > 80).count(),
    }
    daily_data = []
    for i in range(7):
        date = (datetime.datetime.utcnow() - datetime.timedelta(days=i)).date()
        count = db.query(ScanHistory).filter(filter_user, func.date(ScanHistory.created_at) == date).count()
        daily_data.append({"date": date.strftime("%b %d"), "count": count})
    daily_data.reverse()
    brand_counts: Dict[str, int] = {}
    brands_in_db = db.query(ScanHistory.domain).filter(filter_user, ScanHistory.classification == "Phishing", ScanHistory.domain.isnot(None)).all()
    brand_keywords = ["paypal", "chase", "netflix", "microsoft", "google", "apple", "amazon", "coinbase", "metamask", "docusign", "dhl", "fedex"]
    for (dom,) in brands_in_db:
        if not dom:
            continue
        for b in brand_keywords:
            if b in dom.lower():
                brand_counts[b] = brand_counts.get(b, 0) + 1
    most_impersonated = [{"brand": k.title(), "count": v} for k, v in sorted(brand_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    keyword_counts = {"urgent": 0, "password": 0, "login": 0, "verify": 0, "bank": 0, "crypto": 0, "link": 0, "immediately": 0}
    phish_bodies = db.query(ScanHistory.body_preview).filter(filter_user, ScanHistory.classification == "Phishing").all()
    for (body,) in phish_bodies:
        if not body:
            continue
        low = body.lower()
        for kw in keyword_counts:
            if kw in low:
                keyword_counts[kw] += 1
    top_keywords = [{"word": k, "count": v} for k, v in sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:5] if v > 0]
    danger_domains_query = db.query(ScanHistory.domain, func.max(ScanHistory.risk_score)).filter(
        filter_user, ScanHistory.domain.isnot(None), ScanHistory.classification == "Phishing"
    ).group_by(ScanHistory.domain).order_by(func.max(ScanHistory.risk_score).desc()).limit(5).all()
    danger_domains = [{"domain": dom, "risk": r} for dom, r in danger_domains_query if dom]
    countries_query = db.query(ScanHistory.country, func.count(ScanHistory.id)).filter(filter_user, ScanHistory.country.isnot(None)).group_by(ScanHistory.country).all()
    country_distribution = {c or "Unknown": count for c, count in countries_query if c and c != "Unknown"}
    # No fake fallback: return empty dict if no real data
    file_types_query = db.query(ScanHistory.file_type, func.count(ScanHistory.id)).filter(filter_user).group_by(ScanHistory.file_type).all()
    file_type_distribution = {ft or "TXT": count for ft, count in file_types_query if ft}
    asn_counts: Dict[str, int] = {}
    spoofed_headers_count = 0
    all_forensics_rows = db.query(ScanHistory.forensics_data).filter(filter_user, ScanHistory.forensics_data.isnot(None)).all()
    for (f_str,) in all_forensics_rows:
        if not f_str:
            continue
        try:
            f_data = json.loads(f_str)
            geo_info = f_data.get("origin_geolocation")
            if geo_info and geo_info.get("asn") and geo_info["asn"] != "Unknown":
                asn_name = geo_info["asn"]
                asn_counts[asn_name] = asn_counts.get(asn_name, 0) + 1
            hdr = f_data.get("header_forensics")
            if hdr and (hdr.get("return_path_mismatch") or hdr.get("display_name_spoofed")):
                spoofed_headers_count += 1
        except Exception:
            continue
    top_asns = [{"asn": k, "count": v} for k, v in sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    # No fake fallback: empty list if no data
    spoofing_rate = round((spoofed_headers_count / total * 100), 1) if total > 0 else 0.0
    recent_items = db.query(ScanHistory).filter(filter_user).order_by(ScanHistory.created_at.desc()).limit(5).all()
    recent_scans = []
    for item in recent_items:
        indicators = json.loads(item.detected_indicators) if item.detected_indicators else {}
        geo = GeoLocationResult(**json.loads(item.geolocation_data)) if item.geolocation_data else None
        forensics_obj = DigitalForensicsResult(**json.loads(item.forensics_data)) if item.forensics_data else None
        recent_scans.append(PredictResponse(
            id=item.id, user_id=item.user_id, subject=item.subject, sender=item.sender,
            classification=item.classification, confidence_score=item.confidence_score, risk_score=item.risk_score,
            explanation=item.explanation, detected_indicators=indicators, highlighted_text="", xai_keywords=[], created_at=item.created_at,
            threat_type=item.threat_type, geolocation=geo, forensics=forensics_obj
        ))
    return StatsResponse(
        total_scans=total, safe_count=safe, suspicious_count=suspicious, phishing_count=phishing,
        average_confidence=round(avg_conf, 1), risk_distribution=distribution,
        daily_scans=daily_data, weekly_scans=[], most_impersonated_brands=most_impersonated,
        top_phishing_keywords=top_keywords, most_dangerous_domains=danger_domains,
        country_distribution=country_distribution, file_type_distribution=file_type_distribution,
        top_origin_asns=top_asns, header_spoofing_rate=spoofing_rate, recent_scans=recent_scans
    )

# --- Bulk & Export (missing features) ---
from pydantic import BaseModel as _BaseModel

class BulkPredictRequest(_BaseModel):
    texts: List[str]
    sender: Optional[str] = None
    subject: Optional[str] = None

@app.post("/api/bulk/predict", response_model=List[PredictResponse])
@limiter.limit("20/minute")
async def bulk_predict(request: Request, payload: BulkPredictRequest, db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_optional_current_user)):
    if not payload.texts or len(payload.texts) > 20:
        raise HTTPException(status_code=400, detail="Provide 1-20 texts")
    results = []
    for txt in payload.texts:
        sanitized = validate_email_text(txt)
        res = await run_in_threadpool(classifier.predict, sanitized, payload.sender or "", payload.subject or "")
        # Minimal enrichment (no external lookups for bulk to stay fast)
        db_hist = ScanHistory(
            user_id=current_user.id if current_user else None,
            subject=payload.subject or "Bulk Scan", sender=payload.sender or "Bulk",
            body_preview=sanitized[:200], classification=res["classification"],
            confidence_score=res["confidence_score"], risk_score=res["risk_score"],
            explanation=res["explanation"], detected_indicators=json.dumps(res["detected_indicators"]),
            threat_type="Phishing" if res["classification"]=="Phishing" else "Bulk",
            virustotal_results=None, whois_results=None,
            email_auth_results=json.dumps({"spf":"None","dkim":"None","dmarc":"None","is_authenticated":True}),
            attachment_analysis=json.dumps([]), llm_analysis=json.dumps({"danger_explanation":res["explanation"],"social_engineering_techniques":[],"indicators_of_compromise":[],"safety_recommendations":[],"mitre_mappings":[]}),
            domain=None, country="Unknown", origin_country_code="UN", origin_ip=None,
            geolocation_data=None, forensics_data=json.dumps({"forensic_flags":[]}), file_type="BULK"
        )
        db.add(db_hist); db.commit(); db.refresh(db_hist)
        res.update({"id": db_hist.id, "user_id": db_hist.user_id, "subject": db_hist.subject, "sender": db_hist.sender, "created_at": db_hist.created_at, "threat_type": db_hist.threat_type, "virustotal_results": None, "whois_results": None, "email_auth_results": EmailAuthResult(), "attachment_analysis": [], "llm_analysis": None, "geolocation": None, "sender_geolocation": None, "forensics": DigitalForensicsResult(forensic_flags=[])})
        results.append(PredictResponse(**res))
    return results

@app.get("/api/history/export")
def export_history(limit: int = 100, db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_optional_current_user)):
    q = db.query(ScanHistory)
    if current_user and current_user.role != "admin":
        q = q.filter(ScanHistory.user_id == current_user.id)
    rows = q.order_by(ScanHistory.created_at.desc()).limit(min(limit, 1000)).all()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id","created_at","classification","risk_score","confidence","subject","sender","domain","country","threat_type"])
    for r in rows:
        w.writerow([r.id, r.created_at.isoformat() if r.created_at else "", r.classification, r.risk_score, r.confidence_score, r.subject, r.sender, r.domain, r.country, r.threat_type])
    return Response(content=out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=scan_history.csv"})

# --- AI Chat Panel + Recommendations (NVIDIA meta/muse-glimmer-30b) ---
class ChatMessageModel(_BaseModel):
    role: str
    content: str

class ChatRequestModel(_BaseModel):
    message: str
    conversation: Optional[List[ChatMessageModel]] = None
    scan_context: Optional[Dict[str, Any]] = None
    use_history: bool = True

class RecommendRequestModel(_BaseModel):
    scan_data: Dict[str, Any]
    stats: Optional[Dict[str, Any]] = None
    history: Optional[List[Dict[str, Any]]] = None

@app.post("/api/chat")
@limiter.limit("30/minute")
async def chat_endpoint(request: Request, payload: ChatRequestModel, db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_optional_current_user)):
    # Build context from DB if requested
    stats_data = None
    history_data = None
    if payload.use_history:
        try:
            # reuse stats logic (lightweight)
            total = db.query(ScanHistory).count()
            # fetch recent 5 for context
            recent = db.query(ScanHistory).order_by(ScanHistory.created_at.desc()).limit(5).all()
            history_data = [{"id": r.id, "classification": r.classification, "risk_score": r.risk_score, "subject": r.subject, "sender": r.sender, "threat_type": r.threat_type, "created_at": r.created_at.isoformat() if r.created_at else None} for r in recent]
            stats_data = {"total_scans": total, "recent_count": len(history_data)}
        except Exception:
            pass
    # Merge explicit scan_context if provided
    scan_ctx = payload.scan_context or {}
    # Build prompt
    conv = [{"role": m.role, "content": m.content} for m in (payload.conversation or [])]
    messages = build_chat_prompt(payload.message, scan_context=scan_ctx, stats=stats_data, history=history_data, conversation=conv)
    try:
        reply = await run_in_threadpool(call_nvidia_chat, messages)
    except Exception as e:
        logger.warning(f"Chat fallback due to NVIDIA error: {e}")
        # Fallback to local rule-based if NVIDIA fails
        reply = f"Forensic AI (offline fallback): I received your message about '{payload.message[:80]}'. "
        if scan_ctx:
            reply += f"Current scan shows {scan_ctx.get('classification','Unknown')} with risk {scan_ctx.get('risk_score', '?')}/100. "
            if scan_ctx.get('classification') == 'Phishing':
                reply += "Recommended: quarantine, block sender domain, reset credentials if clicked, and report to SOC."
            elif scan_ctx.get('classification') == 'Suspicious':
                reply += "Recommended: verify sender via alternate channel, hover-check URLs, do not enter credentials."
            else:
                reply += "No major threats detected — maintain vigilance and verify senders for sensitive actions."
        else:
            reply += "Ask me about any scan, or paste an email/URL for analysis. I use your scan history and live telemetry for context."
    return {"reply": reply, "model": "meta/muse-glimmer-30b", "scan_context_used": bool(scan_ctx)}

@app.post("/api/chat/recommend")
@limiter.limit("30/minute")
async def recommend_endpoint(request: Request, payload: RecommendRequestModel, db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_optional_current_user)):
    # Enrich with real stats/history if not provided
    stats_data = payload.stats
    history_data = payload.history
    if stats_data is None or history_data is None:
        try:
            total = db.query(ScanHistory).count()
            phishing = db.query(ScanHistory).filter(ScanHistory.classification == "Phishing").count()
            recent = db.query(ScanHistory).order_by(ScanHistory.created_at.desc()).limit(5).all()
            if stats_data is None:
                stats_data = {"total_scans": total, "phishing_count": phishing, "phishing_rate": round(phishing/total*100,1) if total else 0}
            if history_data is None:
                history_data = [{"classification": r.classification, "risk_score": r.risk_score, "threat_type": r.threat_type} for r in recent]
        except Exception:
            pass
    messages = build_recommendation_prompt(payload.scan_data, stats=stats_data, recent_history=history_data)
    try:
        reply = await run_in_threadpool(call_nvidia_chat, messages, 0.6, 0.95, 1024)
    except Exception as e:
        logger.warning(f"Recommend fallback: {e}")
        # Local fallback
        cls = payload.scan_data.get("classification", "Unknown")
        risk = payload.scan_data.get("risk_score", "?")
        reply = f"**Verdict:** {cls} (risk {risk}/100)\n\n**Key risks:** {', '.join(payload.scan_data.get('detected_indicators', {}).keys()) or 'none'}\n\n**Immediate actions:** 1) Do not click links/attachments 2) Verify sender via alternate channel 3) Report to SOC\n\n**Strategic:** This fits a pattern of {stats_data.get('phishing_count', '?')} phishing cases in history — consider blocking similar domains and user training."
    return {"recommendation": reply, "model": "meta/muse-glimmer-30b"}

logger.info("API initialized successfully")

@app.get("/api/extension/download")
def download_extension():
    try:
        zip_data = get_extension_zip_bytes()
        return Response(content=zip_data, media_type="application/zip", headers={"Content-Disposition": "attachment; filename=ai_phishing_detector_extension.zip"})
    except Exception as e:
        logger.exception("Failed to package extension")
        raise HTTPException(status_code=500, detail=f"Failed to package extension: {e}")

from fastapi.staticfiles import StaticFiles

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frontend_dist_path = os.path.join(BASE_DIR, "static", "dist")

if os.path.exists(frontend_dist_path):
    assets_path = os.path.join(frontend_dist_path, "assets")
    if os.path.exists(assets_path):
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")
