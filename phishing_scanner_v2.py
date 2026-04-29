def analyze_email(email_text: str) -> dict:
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

def load_emails_from_file(filename: str):
    emails = []
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            content = file.read()
            raw_emails = content.strip().split('\n\n')
            for email in raw_emails:
                if email.strip():
                    emails.append(email.strip())
    except FileNotFoundError:
        print(f"Error: {filename} not found. Create the file first.")
    return emails

# Test with multiple emails
if __name__ == "__main__":
    sample_file = "sample_emails.txt"
    # Auto-create sample file if missing
    if not open(sample_file, 'a').close():
        with open(sample_file, 'w', encoding='utf-8') as f:
            f.write("""URGENT: Your account will be suspended. Click here to verify your password and login immediately.\n\n""")
            f.write("""Your monthly statement from Wells Fargo is now available. Please log in to view.\n\n""")
            f.write("""IMMEDIATE ACTION REQUIRED: Update your banking details or lose access.\n\n""")
    
    emails = load_emails_from_file(sample_file)
    
    print("=== PHISHING SCANNER v0.2 – Batch Processing ===")
    print(f"Loaded {len(emails)} emails for analysis\n")
    
    total_score = 0
    high_risk_count = 0
    
    for i, email in enumerate(emails, 1):
        result = analyze_email(email)
        print(f"Email {i} Risk: {result['risk_level']} (Score: {result['score']})")
        for finding in result['findings']:
            print(finding)
        print(f"Recommendation: {result['recommendation']}\n")
        
        total_score += result['score']
        if result['risk_level'] == "HIGH":
            high_risk_count += 1
    
    print("=== SUMMARY REPORT ===")
    print(f"Total emails analyzed: {len(emails)}")
    print(f"High-risk emails: {high_risk_count}")
    print(f"Average risk score: {total_score / len(emails):.2f}")
    print("This pattern-based analysis forms the foundation for future ML-based threat classifiers.")