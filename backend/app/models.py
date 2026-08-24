import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")  # "user" or "admin"
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    scans = relationship("ScanHistory", back_populates="user")

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    subject = Column(String, nullable=True)
    sender = Column(String, nullable=True)
    body_preview = Column(Text, nullable=False)
    classification = Column(String, nullable=False)  # "Safe", "Suspicious", "Phishing"
    confidence_score = Column(Float, nullable=False)  # 0.0 to 100.0
    risk_score = Column(Float, nullable=False)  # 0.0 to 100.0
    explanation = Column(Text, nullable=False)
    detected_indicators = Column(Text, nullable=False)  # JSON string of indicators
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # V2 SaaS Upgrade Columns
    threat_type = Column(String, nullable=True)
    virustotal_results = Column(Text, nullable=True)    # JSON string
    whois_results = Column(Text, nullable=True)          # JSON string
    email_auth_results = Column(Text, nullable=True)     # JSON string
    attachment_analysis = Column(Text, nullable=True)    # JSON string
    llm_analysis = Column(Text, nullable=True)           # JSON string (includes MITRE ATT&CK)
    
    # Telemetry Indexing Columns
    domain = Column(String, nullable=True)
    country = Column(String, nullable=True)
    file_type = Column(String, nullable=True)            # "EML", "TXT", "URL"
    
    # Forensics & Geolocation Columns
    forensics_data = Column(Text, nullable=True)        # JSON string containing deep forensic report
    geolocation_data = Column(Text, nullable=True)      # JSON string containing origin geolocation
    origin_country_code = Column(String, nullable=True) # ISO country code (e.g. US, RU, CN)
    origin_ip = Column(String, nullable=True)           # Extracted origin IP address

    # Relationships
    user = relationship("User", back_populates="scans")
