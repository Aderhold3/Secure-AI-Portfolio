def analyze_email(email_text: str) -> dict:
    # Convert to lowercase for easier matching
    text = email_text.lower()
    
    # Common phishing indicators (expand this list as you learn)
    indicators = {
        "urgent": "High-pressure language",
        "password": "Credential request",
        "verify account": "Account verification scam",
        "click here": "Unsolicited link prompt",
        "bank": "Financial impersonation",
        "https://": "Suspicious link (check for typos)",
        "login": "Credential harvesting attempt"
    }
    
    score = 0
    findings = []
    
    for keyword, description in indicators.items():
        if keyword in text:
            score += 1
            findings.append(f"• {description} detected: '{keyword}'")
    
    risk_level = "LOW" if score <= 1 else "MEDIUM" if score <= 3 else "HIGH"
    
    return {
        "risk_level": risk_level,
        "score": score,
        "findings": findings,
        "recommendation": "FLAG for further analysis" if score >= 2 else "Likely legitimate"
    }

# Test with sample emails
if __name__ == "__main__":
    sample_phishing = """
    URGENT: Your account will be suspended. Click here to verify your password and login immediately.
    """
    
    sample_legit = """
    Your monthly statement from Wells Fargo is now available. Please log in to view.
    """
    
    print("=== PHISHING SCANNER v0.1 ===")
    result1 = analyze_email(sample_phishing)
    print(f"Sample 1 Risk: {result1['risk_level']} (Score: {result1['score']})")
    for finding in result1['findings']:
        print(finding)
    print(f"Recommendation: {result1['recommendation']}\n")
    
    result2 = analyze_email(sample_legit)
    print(f"Sample 2 Risk: {result2['risk_level']} (Score: {result2['score']})")
    print(f"Recommendation: {result2['recommendation']}")