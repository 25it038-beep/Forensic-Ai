"""
Safe demo samples for SOC demonstration
"""

DEMO_EMAILS = [
    {
        "name": "Banking Phishing",
        "subject": "Urgent: Verify your account now",
        "sender": "security@paypa1-security.com",
        "text": """Dear Customer,

We detected unusual activity on your PayPal account. Verify your password immediately or your account will be suspended.

https://paypa1-security.com/verify
Do not ignore this request.

Regards,
PayPal Security Team
""",
        "expected": "Phishing"
    },
    {
        "name": "Government Impersonation",
        "subject": "IRS Tax Refund - Action Required",
        "sender": "irs-notify@gov-irs-update.net",
        "text": """Your 2025 tax refund of $1,842 is pending.

Click here to confirm your bank details: http://irs-refund-update.net/claim
You have 24 hours to respond.

IRS Automated System
""",
        "expected": "Phishing"
    },
    {
        "name": "Microsoft Credential Phishing",
        "subject": "Microsoft 365 - Unusual sign-in blocked",
        "sender": "noreply@microsoft-secure-login.com",
        "text": """We blocked a sign-in attempt to your Microsoft 365 account.

Sign in to secure your account: https://microsoft-secure-login.com/signin
If this wasn't you, secure your account now.

Microsoft
""",
        "expected": "Phishing"
    },
    {
        "name": "Business Email Compromise",
        "subject": "Urgent wire transfer request - CEO",
        "sender": "ceo@acme-corp.com",
        "text": """Hi Finance,

Please urgently wire $45,000 to our new vendor for the Q3 project. The account details are below.

Account: 123456789
Routing: 021000021
Reference: Q3-Vendor-Payment

Do not discuss this via email. Time sensitive.

Thanks,
CEO
""",
        "expected": "Suspicious"
    },
    {
        "name": "Legitimate Corporate Email",
        "subject": "Q3 All-Hands Meeting Invitation",
        "sender": "hr@acme-corp.com",
        "text": """Team,

You are invited to the Q3 All-Hands Meeting on Friday 10am PST.
Meeting link: https://acme-corp.com/meet/q3-all-hands

Please review the agenda attached.

Best,
HR Team
""",
        "expected": "Safe"
    }
]

def get_demo_emails():
    return DEMO_EMAILS
