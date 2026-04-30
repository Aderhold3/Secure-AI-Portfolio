# Expanded default IOC list (realistic 2026 threat intelligence - embedded for portability)
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
    text_lower = text.lower()
    matches = [ioc for ioc in iocs if ioc in text_lower]
    
    risk_level = "HIGH" if len(matches) >= 3 else "MEDIUM" if len(matches) >= 1 else "LOW"
    
    return {
        "risk_level": risk_level,
        "ioc_count": len(matches),
        "matches": matches,
        "recommendation": "Immediate investigation required" if risk_level == "HIGH" else "Monitor"
    }

# Test with sample data
if __name__ == "__main__":
    iocs = load_iocs()
    
    # Sample emails/logs to scan
    samples = [
        "URGENT: Click here to verify your account at login.microsoft.com.fake",
        "Your Wells Fargo statement is ready. Please log in.",
        "IMMEDIATE: Update your banking details at bankofamerica-security-alert.com",
        "Security alert: Your Apple ID needs verification at apple-id-verification-scam.com",
        "Your NordVPN account has been breached – click here to reset at nordvpn-account-breach.com",
        "Shared file from Dropbox: fake-google-drive-share.com"
    ]
    
    print("\n=== THREAT INTELLIGENCE PARSER ===")
    for i, sample in enumerate(samples, 1):
        result = scan_for_iocs(sample, iocs)
        print(f"Sample {i} Risk: {result['risk_level']} (IOCs found: {result['ioc_count']})")
        if result['matches']:
            print(f"Matches: {', '.join(result['matches'])}")
        print(f"Recommendation: {result['recommendation']}\n")
    
    print("Efficient lookup patterns like this form the foundation for scalable secure AI pipelines.")