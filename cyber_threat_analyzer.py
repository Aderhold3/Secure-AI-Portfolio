# Reusable Cybersecurity Threat Analyzer Module
# Combines pattern-based email analysis and IOC detection

DEFAULT_IOCS = {
    "login.microsoft.com.fake",
    "urgent-account-verification.com",
    "click-here-to-verify.com",
    "192.168.1.100-malicious",
    "bankofamerica-security-alert.com",
    "phishing-microsoft-support.com",
    "account-suspended-immediate.com",
    "security-update-required.net",
    "paypal-verification-login.com",
    "amazon-account-security-alert.com",
    "192.168.100.50-suspicious",
    "malicious-c2-domain.ru",
    "fake-google-drive-share.com",
    "irs-tax-refund-claim.com",
    "wellsfargo-security-login.com",
    "nordvpn-account-breach.com",
    "discord-verification-link.com",
    "10.0.0.1-malicious-router",
    "apple-id-verification-scam.com",
    "chase-bank-fraud-alert.com",
    "microsoft-365-login-secure.com",
    "dropbox-shared-file-alert.com",
    "slack-verification-required.com",
    "zoom-meeting-invite-scam.com",
    "github-security-token-reset.com",
    "crypto-wallet-recovery-phish.com",
    "aws-console-login-alert.com",
    "heroku-app-deployment-scam.com"
}

def analyze_email(email_text: str) -> dict:
    """Basic pattern-based email threat analysis."""
    text = email_text.lower()
    indicators = {
        "urgent": "High-pressure language",
        "password": "Credential request",
        "verify account": "Account verification scam",
        "click here": "Unsolicited link prompt",
        "bank": "Financial impersonation",
        "https://": "Suspicious link (check for typos)",
        "login": "Credential harvesting attempt"
    }
    
    score = sum(1 for keyword in indicators if keyword in text)
    risk_level = "LOW" if score <= 1 else "MEDIUM" if score <= 3 else "HIGH"
    
    findings = [f"• {desc} detected: '{kw}'" for kw, desc in indicators.items() if kw in text]
    
    return {
        "risk_level": risk_level,
        "score": score,
        "findings": findings,
        "recommendation": "FLAG for further analysis" if score >= 2 else "Likely legitimate"
    }

def load_iocs(filename: str = "known_iocs.txt") -> set:
    """Load IOCs from file. Falls back to expanded default list if file is missing."""
    iocs = set()
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip().lower()
                if line and not line.startswith('#'):
                    iocs.add(line)
        print(f"Loaded {len(iocs)} IOCs from {filename}")
    except FileNotFoundError:
        print(f"File {filename} not found — using expanded default IOC list ({len(DEFAULT_IOCS)} entries)")
        iocs = DEFAULT_IOCS.copy()
    return iocs

def scan_for_iocs(text: str, iocs: set) -> dict:
    """IOC-based threat scan."""
    text_lower = text.lower()
    matches = [ioc for ioc in iocs if ioc in text_lower]
    risk_level = "HIGH" if len(matches) >= 3 else "MEDIUM" if len(matches) >= 1 else "LOW"
    
    return {
        "risk_level": risk_level,
        "ioc_count": len(matches),
        "matches": matches,
        "recommendation": "Immediate investigation required" if risk_level == "HIGH" else "Monitor"
    }

def run_full_analysis(text: str, iocs: set = None) -> dict:
    """Combined analysis using both email patterns and IOCs."""
    if iocs is None:
        iocs = load_iocs()
    
    email_result = analyze_email(text)
    ioc_result = scan_for_iocs(text, iocs)
    
    # Simple combined risk score
    combined_score = email_result["score"] + ioc_result["ioc_count"]
    final_risk = "HIGH" if combined_score >= 4 else "MEDIUM" if combined_score >= 2 else "LOW"
    
    return {
        "final_risk_level": final_risk,
        "email_analysis": email_result,
        "ioc_analysis": ioc_result
    }

# Test the full toolkit when run directly
if __name__ == "__main__":
    iocs = load_iocs()
    
    samples = [
        "URGENT: Click here to verify your account at login.microsoft.com.fake",
        "Your Wells Fargo statement is ready. Please log in.",
        "IMMEDIATE: Update your banking details at bankofamerica-security-alert.com",
        "Security alert: Your Apple ID needs verification at apple-id-verification-scam.com",
        "Your NordVPN account has been breached – click here to reset at nordvpn-account-breach.com"
    ]
    
    print("\n=== CYBER THREAT ANALYZER MODULE ===")
    for i, sample in enumerate(samples, 1):
        result = run_full_analysis(sample, iocs)
        print(f"Sample {i} Final Risk: {result['final_risk_level']}")
        print(f"Email Score: {result['email_analysis']['score']} | IOCs Found: {result['ioc_analysis']['ioc_count']}")
        print(f"Recommendation: {result['email_analysis']['recommendation']}\n")
    
    print("This reusable module is now ready to be imported into larger secure AI systems.")