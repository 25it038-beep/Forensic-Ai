from pydantic import BaseModel, Field, EmailStr
from typing import List, Dict, Optional, Any
from datetime import datetime

# --- User & Auth Schemas ---

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class TokenData(BaseModel):
    email: Optional[str] = None

# --- Threat Intelligence Sub-Schemas ---

class VirusTotalResult(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    reputation: int = 0
    community_votes_harmless: int = 0
    community_votes_malicious: int = 0
    raw_response: Optional[str] = None

class WhoisResult(BaseModel):
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = "Unknown"
    registration_date: Optional[str] = "Unknown"
    expiration_date: Optional[str] = "Unknown"
    updated_date: Optional[str] = "Unknown"
    country: Optional[str] = "Unknown"
    name_servers: Optional[str] = "Unknown"
    is_new_domain: bool = False

class DnsResult(BaseModel):
    ip_address: Optional[str] = "Unknown"
    a_records: List[str] = []
    aaaa_records: List[str] = []
    mx_records: List[str] = []
    txt_records: List[str] = []
    ns_records: List[str] = []
    cname_records: List[str] = []

class SslResult(BaseModel):
    has_ssl: bool = False
    issuer: Optional[str] = "Unknown"
    subject: Optional[str] = "Unknown"
    valid_from: Optional[str] = "Unknown"
    valid_to: Optional[str] = "Unknown"
    signature_algorithm: Optional[str] = "Unknown"
    is_expired: bool = True
    days_remaining: int = 0
    is_self_signed: bool = False

class EmailAuthResult(BaseModel):
    spf: str = "None"      # "Pass", "Fail", "None", "Neutral"
    dkim: str = "None"     # "Pass", "Fail", "None"
    dmarc: str = "None"    # "Pass", "Fail", "None"
    is_authenticated: bool = True

class AttachmentInfo(BaseModel):
    filename: str
    risk_level: str        # "Low", "Medium", "High"
    reason: str
    action: str

# --- Advanced Geolocation & Forensics Schemas ---

class GeoLocationResult(BaseModel):
    ip: Optional[str] = "Unknown"
    country: Optional[str] = "Unknown"
    country_code: Optional[str] = "UN"
    city: Optional[str] = "Unknown"
    region: Optional[str] = "Unknown"
    latitude: Optional[float] = 0.0
    longitude: Optional[float] = 0.0
    isp: Optional[str] = "Unknown"
    asn: Optional[str] = "Unknown"
    org: Optional[str] = "Unknown"
    timezone: Optional[str] = "UTC"
    verification_source: Optional[str] = None

class EmailHop(BaseModel):
    hop_number: int
    from_server: Optional[str] = "Unknown"
    by_server: Optional[str] = "Unknown"
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    delay_seconds: Optional[int] = 0
    geo: Optional[GeoLocationResult] = None

class HeaderForensics(BaseModel):
    originating_ip: Optional[str] = None
    originating_geo: Optional[GeoLocationResult] = None
    hops: List[EmailHop] = []
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    from_header: Optional[str] = None
    message_id: Optional[str] = None
    mailer: Optional[str] = None
    return_path_mismatch: bool = False
    display_name_spoofed: bool = False
    suspicious_mailer: bool = False

class AttachmentForensics(BaseModel):
    filename: str
    size_bytes: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    mime_type: str = "application/octet-stream"
    magic_bytes_match: bool = True
    is_disguised_executable: bool = False
    risk_level: str = "Low"
    details: str = ""

class UrlForensics(BaseModel):
    punycode: Optional[str] = None
    is_homograph: bool = False
    typosquatting_target: Optional[str] = None
    levenshtein_distance: Optional[int] = None
    redirect_hops: List[str] = []
    final_destination: Optional[str] = None
    geo: Optional[GeoLocationResult] = None

class BecAnalysisResult(BaseModel):
    is_bec_threat: bool = False
    bec_type: str = "None" # "Payment Diversion", "Fake Invoice Request", "Executive Impersonation", "Credential Harvesting", "None"
    urgency_level: str = "Low" # "Low", "Medium", "High", "Critical"
    detected_patterns: List[str] = []

class AttributionIntelligence(BaseModel):
    probable_actor_type: str = "Unknown" # "Spoofed Domain / Name", "Compromised Valid Account", "Anonymized Proxy / VPN", "Direct Malicious Infrastructure", "Authorized Infrastructure"
    attribution_confidence: float = 0.0
    infrastructure_type: str = "Standard Mail Server"
    suspected_campaign: Optional[str] = None
    vpn_or_proxy_detected: bool = False
    tor_detected: bool = False
    threat_actor_indicators: List[str] = []

class GraphNode(BaseModel):
    id: str
    label: str
    type: str # "sender", "domain", "ip", "asn", "brand", "attachment", "hash", "campaign"
    threat_level: str = "neutral" # "safe", "warning", "critical", "neutral"

class GraphLink(BaseModel):
    source: str
    target: str
    relationship: str

class CorrelationGraph(BaseModel):
    nodes: List[GraphNode] = []
    links: List[GraphLink] = []

class DigitalForensicsResult(BaseModel):
    header_forensics: Optional[HeaderForensics] = None
    attachment_forensics: List[AttachmentForensics] = []
    url_forensics: Optional[UrlForensics] = None
    origin_geolocation: Optional[GeoLocationResult] = None
    sender_geolocation: Optional[GeoLocationResult] = None
    forensic_risk_score: float = 0.0
    forensic_flags: List[str] = []
    bec_analysis: Optional[BecAnalysisResult] = None
    attribution: Optional[AttributionIntelligence] = None
    correlation_graph: Optional[CorrelationGraph] = None

class MitreMapping(BaseModel):
    id: str                # e.g. "T1566"
    name: str              # e.g. "Phishing"
    description: str

class LlmAnalysisResult(BaseModel):
    danger_explanation: str
    social_engineering_techniques: List[str]
    indicators_of_compromise: List[str]
    safety_recommendations: List[str]
    mitre_mappings: List[MitreMapping]

# --- Main API Responses ---

class EmailPredictRequest(BaseModel):
    text: str = Field(..., min_length=1, description="The raw email body text to analyze")

class KeywordImportance(BaseModel):
    word: str
    weight: float
    type: str  # "danger" or "safe"

class PredictResponse(BaseModel):
    id: Optional[int] = None
    user_id: Optional[int] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    classification: str  # "Safe", "Suspicious", "Phishing"
    confidence_score: float
    risk_score: float
    explanation: str
    detected_indicators: Dict[str, Any]
    highlighted_text: str
    xai_keywords: List[KeywordImportance] = []
    created_at: Optional[datetime] = None
    
    # V2 Upgrades
    threat_type: Optional[str] = "Unknown"
    virustotal_results: Optional[VirusTotalResult] = None
    whois_results: Optional[WhoisResult] = None
    dns_results: Optional[DnsResult] = None
    ssl_results: Optional[SslResult] = None
    email_auth_results: Optional[EmailAuthResult] = None
    attachment_analysis: List[AttachmentInfo] = []
    llm_analysis: Optional[LlmAnalysisResult] = None
    
    # Advanced Forensics & Geolocation
    geolocation: Optional[GeoLocationResult] = None
    sender_geolocation: Optional[GeoLocationResult] = None
    forensics: Optional[DigitalForensicsResult] = None
    
    # OCR Preview (Extracted text if scanned)
    ocr_extracted_text: Optional[str] = None

    class Config:
        from_attributes = True

class UrlAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, description="The URL to analyze for security threats")

class UrlAnalyzeResponse(BaseModel):
    id: Optional[int] = None
    url: str
    domain: str
    risk_score: float
    status: str  # "Safe", "Suspicious", "Dangerous"
    reasons: List[str]
    threat_type: str
    advice: str
    created_at: Optional[datetime] = None
    
    # V2 Upgrades
    virustotal_results: Optional[VirusTotalResult] = None
    whois_results: Optional[WhoisResult] = None
    dns_results: Optional[DnsResult] = None
    ssl_results: Optional[SslResult] = None
    
    # Forensics & Geolocation
    geolocation: Optional[GeoLocationResult] = None
    sender_geolocation: Optional[GeoLocationResult] = None
    forensics: Optional[DigitalForensicsResult] = None

class StatsResponse(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    phishing_count: int
    average_confidence: float
    risk_distribution: Dict[str, int]
    
    # V2 Threat Intel Advanced Metrics
    daily_scans: List[Dict[str, Any]]              # e.g., [{"date": "2026-06-29", "count": 10}]
    weekly_scans: List[Dict[str, Any]]
    most_impersonated_brands: List[Dict[str, Any]] # e.g., [{"brand": "paypal", "count": 4}]
    top_phishing_keywords: List[Dict[str, Any]]    # e.g., [{"word": "urgent", "count": 15}]
    most_dangerous_domains: List[Dict[str, Any]]   # e.g., [{"domain": "netflix-update.com", "risk": 95}]
    country_distribution: Dict[str, int]
    file_type_distribution: Dict[str, int]         # e.g., {"EML": 12, "TXT": 8, "URL": 20}
    top_origin_asns: List[Dict[str, Any]] = []      # e.g., [{"asn": "AS13335 Cloudflare", "count": 8}]
    header_spoofing_rate: float = 0.0              # Percentage of scans with spoofed headers
    
    recent_scans: List[PredictResponse]
