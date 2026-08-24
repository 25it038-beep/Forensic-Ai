import re
from typing import Dict, List, Any

# Urgent language patterns
URGENT_PATTERNS = [
    r"\burgent\b", r"\baction required\b", r"\bimmediate\b", r"\battention\b",
    r"\bsuspended\b", r"\brestricted\b", r"\bblocked\b", r"\bcompromised\b",
    r"\bexpire\b", r"\bwithin \d+ hours\b", r"\bterminate\b", r"\bdeactivate\b",
    r"\bsecurity breach\b"
]

# Fake login / credential harvesting patterns (High Precision)
LOGIN_PATTERNS = [
    r"\bverify your identity\b",
    r"\bconfirm your account credentials\b",
    r"\bupdate your login credentials\b",
    r"\bre-enter your login\b",
    r"\bclick here to log in\b",
    r"\blogin to verify\b",
    r"\blogin to unlock\b",
    r"\bconfirm your password\b",
    r"\bunlock your suspended account\b"
]

# Password requests
PASSWORD_PATTERNS = [
    r"\benter your password\b", r"\bverify your password\b", r"\bsubmit your password\b",
    r"\bpin code\b", r"\bsecurity phrase\b", r"\bseed phrase\b",
    r"\brecovery phrase\b", r"\bprivate key\b", r"\b2fa code\b"
]

# Banking & financial fraud patterns
BANKING_PATTERNS = [
    r"\bwire transfer request\b", r"\brouting number\b", r"\benter your bank account\b",
    r"\bupdate direct deposit\b", r"\bcredit card number\b", r"\bdebit card number\b",
    r"\bcvv code\b", r"\benter your ssn\b", r"\bsocial security number\b"
]

# Financial scams / Gift cards
FINANCIAL_SCAM_PATTERNS = [
    r"\bgift card\b", r"\bgoogle play card\b", r"\bitunes gift\b", r"\bamazon gift card\b",
    r"\blottery winner\b", r"\bwon a prize\b", r"\bcash prize winner\b", r"\bunclaimed funds\b",
    r"\birs tax refund verification\b"
]

# Crypto scams
CRYPTO_PATTERNS = [
    r"\bmetamask wallet\b", r"\bseed phrase\b", r"\bprivate key\b",
    r"\bconnect your crypto wallet\b", r"\bairdrop claim\b", r"\btrust wallet verification\b"
]

def extract_urls(text: str) -> List[str]:
    """Extract all URLs from text."""
    return re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)

def get_domain(url: str) -> str:
    """Extract domain from a URL."""
    # Remove http:// or https://
    domain = re.sub(r'^https?://', '', url)
    # Remove path, query params, etc.
    domain = domain.split('/')[0]
    # Remove port
    domain = domain.split(':')[0]
    return domain.lower()

def is_ip_address(domain: str) -> bool:
    """Check if the domain is an IP address."""
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))

def analyze_indicators(text: str, sender: str = "", subject: str = "", attachments: List[str] = None) -> Dict[str, Any]:
    """
    Analyze the email and return a dictionary of triggered indicators.
    Each indicator has a boolean 'triggered' flag and a 'description' or list of matches.
    """
    text_lower = text.lower()
    subject_lower = subject.lower()
    combined_text = f"{subject_lower}\n{text_lower}"
    
    indicators = {
        "urgent_language": {"triggered": False, "details": []},
        "suspicious_urls": {"triggered": False, "details": []},
        "fake_login": {"triggered": False, "details": []},
        "password_request": {"triggered": False, "details": []},
        "banking_scam": {"triggered": False, "details": []},
        "financial_fraud": {"triggered": False, "details": []},
        "crypto_scam": {"triggered": False, "details": []},
        "grammar_issues": {"triggered": False, "details": []},
        "spoofed_sender": {"triggered": False, "details": []},
        "dangerous_attachments": {"triggered": False, "details": []}
    }
    
    # 1. Urgent Language
    for pattern in URGENT_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            indicators["urgent_language"]["triggered"] = True
            indicators["urgent_language"]["details"].extend(matches)
            
    # 2. Fake Login Requests
    for pattern in LOGIN_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            indicators["fake_login"]["triggered"] = True
            indicators["fake_login"]["details"].extend(matches)
            
    # 3. Password Requests
    for pattern in PASSWORD_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            indicators["password_request"]["triggered"] = True
            indicators["password_request"]["details"].extend(matches)
            
    # 4. Banking Scams
    for pattern in BANKING_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            indicators["banking_scam"]["triggered"] = True
            indicators["banking_scam"]["details"].extend(matches)
            
    # 5. Financial Fraud
    for pattern in FINANCIAL_SCAM_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            indicators["financial_fraud"]["triggered"] = True
            indicators["financial_fraud"]["details"].extend(matches)
            
    # 6. Crypto Scams
    for pattern in CRYPTO_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            indicators["crypto_scam"]["triggered"] = True
            indicators["crypto_scam"]["details"].extend(matches)

    # 7. Suspicious URLs
    urls = extract_urls(text)
    suspicious_domains = []
    
    for url in urls:
        domain = get_domain(url)
        # Check if URL uses an IP address
        if is_ip_address(domain):
            indicators["suspicious_urls"]["triggered"] = True
            indicators["suspicious_urls"]["details"].append(f"IP-based URL: {url}")
        
        # Check for too many subdomains (more than 4)
        if len(domain.split('.')) > 4:
            indicators["suspicious_urls"]["triggered"] = True
            indicators["suspicious_urls"]["details"].append(f"Excessive subdomains: {domain}")
            
        # Check for typosquatting / brand hijacking in domain (e.g. chase-security, paypaI, metamask-wallet)
        brand_keywords = ["paypal", "chase", "bank", "netflix", "microsoft", "google", "apple", "amazon", "coinbase", "metamask", "docusign", "dhl", "fedex"]
        for brand in brand_keywords:
            # If the brand is in the domain, but it's not the actual official domain (we simplify: contains brand and hyphen, or brand is a subdomain but top level is different)
            if brand in domain:
                official_domains = [f"{brand}.com", f"{brand}.net", f"{brand}.org", f"officials{brand}.com", f"my{brand}.com"]
                is_official = any(off in domain for off in official_domains)
                # Simple heuristic: if it has hyphens or is longer than just the brand, flag it
                if not is_official and (len(domain.replace(brand, '')) > 4 or '-' in domain):
                    indicators["suspicious_urls"]["triggered"] = True
                    indicators["suspicious_urls"]["details"].append(f"Potential brand impersonation: {domain} mimicking {brand}")
                    
    # 8. Spoofed Sender
    if sender and urls:
        sender_domain = sender.split('@')[-1].lower() if '@' in sender else ""
        if sender_domain:
            for url in urls:
                url_domain = get_domain(url)
                # If email claims to be from a major brand but links to another domain
                brands = ["paypal", "chase", "netflix", "microsoft", "google", "apple", "amazon", "coinbase", "metamask"]
                for brand in brands:
                    if brand in sender_domain and brand not in url_domain:
                        # Major brand spoofing
                        indicators["spoofed_sender"]["triggered"] = True
                        indicators["spoofed_sender"]["details"].append(
                            f"Sender domain '{sender_domain}' claims to be '{brand}', but links point to '{url_domain}'"
                        )
                        break

    # 9. Grammar Issues (Heuristic: excessive exclamation marks, poor capitalization)
    exclamation_count = text.count('!')
    if exclamation_count > 4:
        indicators["grammar_issues"]["triggered"] = True
        indicators["grammar_issues"]["details"].append(f"Excessive exclamation marks ({exclamation_count})")
        
    # Check for lowercase at start of sentences (simple check)
    sentences = re.split(r'[.!?]\s+', text)
    lowercase_starts = 0
    for s in sentences:
        if s and s[0].islower() and not s.startswith(('http', 'www')):
            lowercase_starts += 1
    if lowercase_starts > 3:
        indicators["grammar_issues"]["triggered"] = True
        indicators["grammar_issues"]["details"].append("Multiple sentences starting with lowercase letters")

    # 10. Dangerous Attachments
    if attachments:
        dangerous_extensions = ['.exe', '.scr', '.bat', '.vbs', '.cmd', '.js', '.wsf', '.pif', '.zip', '.rar', '.cab', '.dmg', '.pkg']
        for att in attachments:
            ext = '.' + att.split('.')[-1].lower() if '.' in att else ""
            if ext in dangerous_extensions:
                indicators["dangerous_attachments"]["triggered"] = True
                indicators["dangerous_attachments"]["details"].append(f"Dangerous attachment file type: {att}")

    # Deduplicate details
    for key in indicators:
        indicators[key]["details"] = list(set(indicators[key]["details"]))

    return indicators
