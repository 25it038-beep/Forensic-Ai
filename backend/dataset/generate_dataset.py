import pandas as pd
import random
import os

# Set seed for reproducibility
random.seed(42)

# Templates for Safe Emails (Label: 0)
safe_subjects = [
    "Weekly Team Sync Meeting",
    "Project Status Update - Q3 Deliverables",
    "Lunch plans for tomorrow?",
    "Code Review: Feature/Auth-Module",
    "Design System Feedback",
    "Vacation request approval",
    "Welcome to the team, Sarah!",
    "Company Newsletter - June 2026",
    "RE: Question about the database schema",
    "Gym membership reimbursement policy",
    "New office layout plan",
    "Happy Birthday!",
    "Discussion on customer feedback",
    "Onboarding schedule for Monday",
    "Notes from today's brainstorming session"
]

safe_bodies = [
    "Hi team, just a reminder that our weekly sync is tomorrow at 10 AM. We'll go over the Q3 deliverables and blockers. See you there!",
    "Hey, are you free for lunch tomorrow? Thinking of trying that new taco place down the street. Let me know if you want to join.",
    "Hi, I've submitted the pull request for the authentication module. Please review the changes, especially the token refresh logic. Thanks!",
    "Hello, here is the updated design system document. Please review and leave your comments by Friday EOD so we can finalize the layout.",
    "Hi, your vacation request for July 5th to July 12th has been approved. Make sure to set your out-of-office message in Outlook.",
    "Let's welcome Sarah to our engineering team! She joins us as a Senior Frontend Developer. Drop by her desk to say hello or send a welcome message.",
    "Dear employees, here is this month's newsletter. We have exciting updates about our new office space and the upcoming team building event in July.",
    "Hi John, regarding the database schema, I think we should add an index to the email column. It will speed up our history queries significantly. Let me know your thoughts.",
    "Hello, just a reminder that the deadline for gym membership reimbursement claims is the 15th of every month. Submit your receipts via the HR portal.",
    "Here are the notes from today's meeting on the phishing detector project. Action items: Harshan to work on the UI, team to review the ML model.",
    "Hey, thanks for helping me out with the bug yesterday. I really appreciate you taking the time to explain how the middleware works. Let's grab coffee sometime.",
    "Hi all, the new office layout has been finalized. We will start moving desks next weekend. Please pack your belongings by Friday afternoon.",
    "Hi, could you please send me the report on customer satisfaction scores? I need to include it in the presentation for the board meeting next week.",
    "Hi, I've reviewed the onboarding schedule for next week's new hires. It looks solid, but let's make sure we have the laptops ready by Monday morning.",
    "Hello, just wanted to follow up on our conversation earlier. I've updated the API documentation with the new endpoints. You can find it in the docs folder."
]

# Templates for Suspicious Emails (Label: 1)
suspicious_subjects = [
    "Special Offer: 80% off all developer tools",
    "Your package could not be delivered - Update address",
    "URGENT: Review your recent transaction",
    "Invoices outstanding for your account",
    "Job Offer: Work from home and earn $5000/week",
    "Unusual login attempt detected",
    "Congratulations! You won a gift card",
    "Update your subscription billing details",
    "Verify your email to avoid service disruption",
    "Secure your account now",
    "You have a new private message",
    "Action Required: Confirm your newsletter subscription",
    "System maintenance: Backup your files",
    "Shared document: 'Project_Budget_2026.xlsx'",
    "Earn rewards by completing this quick survey"
]

suspicious_bodies = [
    "Hello, we noticed you haven't claimed your 80% discount on our developer suite. This offer expires in 24 hours. Click here to claim: http://cheap-dev-tools-now.com/discount",
    "Dear customer, your parcel is held at our warehouse due to an incorrect address. To redeliver, please update your details at http://parcel-delivery-tracking-update.net",
    "Alert: A transaction of $450.00 was made on your account from an unrecognized device. If this wasn't you, please review it immediately at http://security-alert-check-activity.com",
    "Hi, we found outstanding invoices on your account. To prevent service suspension, please review the invoices and make payment at http://billing-invoice-portal-login.com",
    "We are hiring! Work from home just 2 hours a day and earn up to $5000 per week. No experience required. Apply now at http://easy-money-careers-online.org/apply",
    "Warning: An unusual login attempt was detected from IP 198.162.1.99 in Russia. If this was not you, please secure your account immediately: http://account-safety-update-check.com",
    "Congratulations! Your email was selected as the winner of a $500 Amazon Gift Card. To claim your prize, fill out this short survey: http://gift-rewards-winner-center.net/claim",
    "Your Netflix subscription could not be renewed. Please update your payment method to continue watching without interruption: http://netflix-billing-update-support.com",
    "To comply with new security regulations, all users must verify their email addresses. Failure to verify within 48 hours will result in account suspension: http://email-verification-verify.org",
    "A security patch is required for your account. Please log in to our secure portal to apply the update: http://secure-login-portal-patch.net/login",
    "You have received a new private message from a colleague. Click the link below to view the message and reply: http://message-center-portal-inbox.com/view",
    "Please confirm your subscription to the Daily Crypto Alert newsletter. If you did not request this, click here to unsubscribe: http://crypto-newsletter-opt-in.net",
    "Our servers will undergo scheduled maintenance tonight. To prevent data loss, please backup your files to our cloud server: http://system-maintenance-backup-cloud.com",
    "John has shared a document with you via OneDrive: 'Project_Budget_2026.xlsx'. Click here to view and edit the document: http://onedrive-sharepoint-document-view.net/budget",
    "Help us improve our service and get a $20 reward. Complete this 3-minute survey about your recent experience: http://customer-survey-rewards-feedback.com"
]

# Templates for Phishing Emails (Label: 2)
phishing_subjects = [
    "URGENT: Your Bank Account Has Been Suspended!",
    "Verify your PayPal account immediately",
    "Security Alert: Reset your password now",
    "Immediate Action Required: IRS Tax Refund Notification",
    "Suspicious Activity Detected on your Credit Card",
    "Your Microsoft account was accessed from a new location",
    "Inbound Wire Transfer Pending - Verification Required",
    "URGENT: Coinbase Account Restricted - Action Required",
    "MetaMask Wallet Security Update - Backup phrase required",
    "DocuSign: Please sign the urgent contract",
    "HR: Update your direct deposit banking details immediately",
    "Your Apple ID has been locked for security reasons",
    "DHL Express: Your shipment requires immediate custom clearance",
    "CEO Request: Buy Google Play Gift Cards for clients",
    "Urgent: Unauthorized access to your email account"
]

phishing_bodies = [
    "Dear Customer, we detected multiple failed login attempts on your online banking account. For your security, we have temporarily suspended your account. To reactivate it, you must verify your identity immediately. Please click the link below to log in and update your credentials: http://chase-bank-security-verification.com/login. Failure to do so within 12 hours will result in permanent account closure.",
    "PayPal Alert: Your account has been limited due to suspicious activity. To restore your account access, please upload a copy of your government ID and verify your credit card details on our secure server: http://paypal-resolution-center-login.com/security. Thank you for helping us keep PayPal safe.",
    "Attention: Your password will expire in 2 hours. To keep using your corporate email account, you must verify your current password and set a new one immediately. Click here to reset: http://outlook-office365-login-verify.com/reset. Failure to update will block your email access.",
    "IRS Notice: You are eligible to receive a tax refund of $1,420.50. Due to a processing error, we were unable to deposit this automatically. To claim your refund, please fill out the tax refund form with your bank account number and Social Security Number (SSN) here: http://irs-gov-tax-refund-portal.net/claim. Do not reply to this email.",
    "Urgent Security Notification: Our fraud prevention system detected an unauthorized charge of $1,899.99 on your credit card at BestBuy.com. If you did not authorize this transaction, you must dispute it immediately by logging into our cardholder services: http://visa-fraud-prevention-dispute.com/verify. Failure to act will hold you liable for the charges.",
    "Your Microsoft account (harshan@company.com) was accessed from an unrecognized device in Beijing, China. If this wasn't you, please change your password immediately to secure your files: http://microsoft-account-security-alert.com/login. If you do not verify your account, we will block access.",
    "We have received a wire transfer of $12,500.00 to your account. However, the transaction is currently pending because the sender's bank requires additional identity verification. Please log in to your account and complete the verification form: http://bank-wire-transfer-processing.net/verify. Once verified, the funds will be credited to your account.",
    "Coinbase Security Alert: Your account has been restricted due to a violation of our terms of service. To lift the restriction and withdraw your funds, you must verify your identity and submit your 2FA recovery code: http://coinbase-account-verification-support.com/identity. Please act quickly to avoid asset liquidation.",
    "MetaMask Notice: A critical vulnerability has been discovered in our smart contracts. To protect your cryptocurrency assets, you must upgrade your wallet to the new secure protocol. Please import your wallet using your 12-word seed phrase on our secure update page: http://metamask-wallet-security-patch.com/upgrade. If you do not upgrade, your funds may be lost.",
    "You have received a new document via DocuSign from 'Finance Department'. Document name: 'Termination_Notice_and_Severance.pdf'. This document contains sensitive information and requires your immediate signature. Click here to review and sign: http://docusign-envelope-signing-portal.com/document. Do not share this link with anyone.",
    "Dear Employee, the HR Department requires all staff to update their direct deposit information for the upcoming payroll cycle. We are moving to a new payroll provider. Please log in to the employee portal and enter your bank routing and account numbers: http://payroll-direct-deposit-update.com/hr. If you do not update by Friday, your paycheck will be delayed.",
    "Your Apple ID has been locked because we detected unauthorized login attempts. To unlock your account and restore access to iCloud, App Store, and Apple Pay, you must verify your security questions and credit card information: http://appleid-verification-support-icloud.com. Thank you, Apple Support.",
    "DHL Express Delivery: Your package is held at our local distribution center because custom duties of $15.40 have not been paid. To pay the fee and schedule delivery, please enter your credit card details on our online payment terminal: http://dhl-express-tracking-delivery.com/customs. Packages not claimed within 3 days will be returned to sender.",
    "Hi, I'm in a board meeting right now and cannot take calls. I need you to do a quick task for me. Please purchase 5 Google Play gift cards of $100 each for some key clients. Scratch the back and email me the codes immediately. I will have HR reimburse you tomorrow. Treat this as urgent. Thanks, CEO.",
    "Warning! We detected a security breach on your email account. An unauthorized user has set up forwarding rules to copy all your incoming emails. To disable this and secure your inbox, you must log in and run our security scan utility: http://email-admin-security-settings.com/scan. Act immediately to protect your privacy."
]

# Generate large synthetic dataset
data = []

# Generate Safe Emails (Label: 0)
for i in range(250):
    subject = random.choice(safe_subjects)
    body = random.choice(safe_bodies)
    # Add some randomness to avoid identical rows
    subject_addon = f" (Ref: {random.randint(100, 999)})" if random.random() > 0.5 else ""
    body_addon = f"\n\nBest regards,\n{random.choice(['John', 'Sarah', 'Alex', 'David', 'Emma', 'Michael'])}"
    text = f"Subject: {subject}{subject_addon}\n\n{body}{body_addon}"
    data.append({"text": text, "label": 0})

# Generate Suspicious Emails (Label: 1)
for i in range(200):
    subject = random.choice(suspicious_subjects)
    body = random.choice(suspicious_bodies)
    subject_addon = f" - Urgent Update" if random.random() > 0.7 else ""
    body_addon = f"\n\nRegards,\nSupport Team"
    text = f"Subject: {subject}{subject_addon}\n\n{body}{body_addon}"
    data.append({"text": text, "label": 1})

# Generate Phishing Emails (Label: 2)
for i in range(250):
    subject = random.choice(phishing_subjects)
    body = random.choice(phishing_bodies)
    subject_addon = f" !!!" if random.random() > 0.5 else ""
    body_addon = f"\n\nSincerely,\nSecurity Department"
    text = f"Subject: {subject}{subject_addon}\n\n{body}{body_addon}"
    data.append({"text": text, "label": 2})

# Shuffle dataset
random.shuffle(data)

# Create DataFrame
df = pd.DataFrame(data)

# Ensure directory exists
os.makedirs("c:\\Users\\BS.Harshan seliyan\\OneDrive\\Desktop\\email  supicious detector\\backend\\dataset", exist_ok=True)

# Save to CSV
csv_path = "c:\\Users\\BS.Harshan seliyan\\OneDrive\\Desktop\\email  supicious detector\\backend\\dataset\\emails.csv"
df.to_csv(csv_path, index=False)

print(f"Dataset generated successfully with {len(df)} rows.")
print(df['label'].value_counts())
