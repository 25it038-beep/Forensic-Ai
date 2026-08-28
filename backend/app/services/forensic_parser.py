"""
Forensic Email Ingestion Service
Normalizes .eml / raw headers / body into structured forensic object.
Preserves existing workflows, adds RFC-compliant header analysis.
"""

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Any, Optional
from datetime import datetime

def parse_eml_bytes(content: bytes) -> Dict[str, Any]:
    msg = BytesParser(policy=policy.default).parsebytes(content)
    return _normalize_message(msg)

def parse_raw_email(raw_text: str) -> Dict[str, Any]:
    try:
        msg = email.parser.Parser(policy=policy.default).parsestr(raw_text)
        return _normalize_message(msg)
    except Exception:
        # Fallback to regex extraction
        return _regex_fallback(raw_text)

def _normalize_message(msg: email.message.EmailMessage) -> Dict[str, Any]:
    def get_header(name: str) -> Optional[str]:
        val = msg.get(name)
        return val.strip() if val else None

    subject = get_header('Subject') or ""
    sender = get_header('From') or ""
    recipient = get_header('To') or ""
    reply_to = get_header('Reply-To')
    return_path = get_header('Return-Path')
    message_id = get_header('Message-ID')
    date_str = get_header('Date')
    received_chain = msg.get_all('Received') or []
    auth_results = get_header('Authentication-Results')
    dkim_sig = get_header('DKIM-Signature')

    # Body extraction
    body = ""
    html_body = ""
    attachments_meta = []
    extracted_urls = []
    
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get('Content-Disposition', '')
            if part.get_content_maintype() == 'text':
                try:
                    data = part.get_content()
                    if ctype == 'text/plain':
                        body += data + "\n"
                    elif ctype == 'text/html':
                        html_body += data + "\n"
                except Exception:
                    pass
            elif disp and 'attachment' in disp:
                filename = part.get_filename() or 'unknown'
                size = len(part.get_payload(decode=True) or b'')
                attachments_meta.append({"filename": filename, "size": size})
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    # Extract URLs
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)
    extracted_urls = url_pattern.findall(body + "\n" + html_body)

    # Extract IPs from Received
    ips = []
    for rec in received_chain:
        ip_match = re.findall(r'[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}', rec)
        ips.extend(ip_match)

    # Timestamps
    timestamps = []
    for rec in received_chain:
        # crude timestamp extraction
        ts_match = re.search(r';\s*(.+)$', rec)
        if ts_match:
            timestamps.append(ts_match.group(1).strip())

    return {
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "date": date_str,
        "received_chain": received_chain,
        "authentication_results": auth_results,
        "dkim_signature": dkim_sig,
        "body": body.strip(),
        "html_body": html_body.strip(),
        "attachments": attachments_meta,
        "extracted_urls": extracted_urls,
        "extracted_ips": ips,
        "timestamps": timestamps,
        "mime_version": get_header('MIME-Version'),
        "content_type": get_header('Content-Type')
    }

def _regex_fallback(raw_text: str) -> Dict[str, Any]:
    def find_re(header):
        m = re.search(rf'^{header}:\s*(.+)$', raw_text, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None

    subject = find_re('Subject') or ""
    sender = find_re('From') or ""
    recipient = find_re('To') or ""
    reply_to = find_re('Reply-To')
    return_path = find_re('Return-Path')
    message_id = find_re('Message-ID')
    date_str = find_re('Date')
    received = re.findall(r'^Received:.*$', raw_text, re.MULTILINE | re.IGNORECASE)
    body = re.sub(r'^.*\r?\n\r?\n', '', raw_text, flags=re.DOTALL)
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)
    extracted_urls = url_pattern.findall(body)
    ips = []
    for rec in received:
        ip_match = re.findall(r'[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}', rec)
        ips.extend(ip_match)
    return {
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "date": date_str,
        "received_chain": received,
        "authentication_results": None,
        "dkim_signature": None,
        "body": body.strip(),
        "html_body": "",
        "attachments": [],
        "extracted_urls": extracted_urls,
        "extracted_ips": ips,
        "timestamps": [],
        "mime_version": None,
        "content_type": None
    }
