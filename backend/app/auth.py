import os
import hashlib
import hmac
import base64
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .database import get_db
from .models import User

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-prod-please-override")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS", "24"))

# Simple PBKDF2 password hashing (no extra deps)
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt + dk).decode()

def verify_password(plain: str, hashed: str) -> bool:
    try:
        raw = base64.b64decode(hashed.encode())
        salt, stored = raw[:16], raw[16:]
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, 100_000)
        return hmac.compare_digest(dk, stored)
    except Exception:
        return False

# Minimal JWT without external deps (HS256)
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": int(expire.timestamp())})
    header = {"alg": ALGORITHM, "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(to_encode, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    s = _b64url_encode(sig)
    return f"{h}.{p}.{s}"

def decode_token(token: str) -> Dict[str, Any]:
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        signing_input = f"{h_b64}.{p_b64}".encode()
        expected = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
        sig = _b64url_decode(s_b64)
        if not hmac.compare_digest(expected, sig):
            raise ValueError("Invalid signature")
        payload = json.loads(_b64url_decode(p_b64).decode())
        if payload.get("exp") and payload["exp"] < int(time.time()):
            raise ValueError("Token expired")
        return payload
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")

security = HTTPBearer(auto_error=False)

def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    # 1. Check for Clerk identity headers
    clerk_email = request.headers.get("X-Clerk-User-Email") or request.headers.get("x-clerk-user-email")
    clerk_id = request.headers.get("X-Clerk-User-Id") or request.headers.get("x-clerk-user-id")
    
    if clerk_email and clerk_email.strip():
        norm_email = clerk_email.strip().lower()
        user = db.query(User).filter(User.email == norm_email).first()
        if not user:
            user = User(
                email=norm_email,
                hashed_password=f"clerk_{clerk_id or 'oauth'}",
                role="admin" if "admin" in norm_email else "user",
                is_active=True,
                is_verified=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return user

    # 2. Check for Bearer JWT token
    if not credentials or not credentials.credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        email = payload.get("sub")
        if not email:
            return None
        user = db.query(User).filter(User.email == email.strip().lower()).first()
        return user
    except Exception:
        return None

def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    user = get_optional_current_user(request=request, credentials=credentials, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive")
    return user
