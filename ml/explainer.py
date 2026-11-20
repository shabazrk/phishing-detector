"""
Explainable AI (XAI) Engine for Phishing Detection.
Converts extracted mathematical and structural features into human-readable,
actionable security insights, addressing the HTTPS fallacy and technical flags.
"""

from typing import Dict, Any, List


def explain_url(raw_url: str, features: Dict[str, Any], phishing_prob: float) -> Dict[str, Any]:
    """
    Generates an Explainable AI (XAI) report for a given URL and its ML prediction.
    """
    findings: List[Dict[str, str]] = []
    recommendations: List[str] = []

    # Risk categorization
    risk_percentage = round(phishing_prob * 100, 1)
    if risk_percentage >= 70:
        verdict = "PHISHING"
        risk_level = "HIGH RISK"
        badge_color = "red"
    elif risk_percentage >= 35:
        verdict = "SUSPICIOUS"
        risk_level = "MEDIUM RISK"
        badge_color = "amber"
    else:
        verdict = "LEGITIMATE"
        risk_level = "SAFE"
        badge_color = "emerald"

    # 1. Dedicated HTTPS Analysis (Addressing the HTTPS weak points directly)
    is_https = features.get("is_https", 0) == 1
    https_token_spoof = features.get("https_token_in_hostname", 0) == 1
    protocol_mismatch = features.get("https_http_protocol_mismatch", 0) == 1
    free_cloud = features.get("free_cloud_host", 0) == 1

    if https_token_spoof:
        findings.append({
            "severity": "CRITICAL",
            "title": "HTTPS Token Spoofing in Hostname",
            "description": "The URL includes the string 'https' or 'ssl' inside its domain/subdomain name. Attackers use this trick to mislead users into believing the site is secure."
        })

    if protocol_mismatch:
        findings.append({
            "severity": "HIGH",
            "title": "Protocol Scheme Mismatch",
            "description": "The URL text contains 'https', but the actual connection protocol is insecure 'http://'. This is an intentional visual deception."
        })

    if is_https:
        if risk_percentage >= 40:
            https_summary = {
                "status": "Encrypted Connection (Deceptive)",
                "note": "This URL uses HTTPS with SSL/TLS encryption. However, modern phishing attacks regularly use valid, free certificates (e.g. Let's Encrypt). Encryption only protects data in transit; it DOES NOT guarantee the site owner is trustworthy.",
                "badge": "warning"
            }
        else:
            https_summary = {
                "status": "Valid HTTPS Protocol",
                "note": "Connection is encrypted with HTTPS, matching standard security protocols for benign web services.",
                "badge": "safe"
            }
    else:
        https_summary = {
            "status": "Insecure HTTP Protocol",
            "note": "This website does not use HTTPS encryption. Any credentials or passwords entered can be intercepted in plain text over the network.",
            "badge": "critical"
        }
        findings.append({
            "severity": "MEDIUM",
            "title": "Missing Transport Encryption (HTTP Only)",
            "description": "Unencrypted HTTP protocol detected. Legitimate authentication portals never run on unencrypted HTTP."
        })

    # 2. Typosquatting / Brand Imitation
    if features.get("typosquatting_risk", 0) == 1:
        findings.append({
            "severity": "CRITICAL",
            "title": "Brand Impersonation / Typosquatting Detected",
            "description": "The domain name closely mimics a well-known brand (e.g. PayPal, Google, Amazon, Microsoft) with slight character substitutions or hyphens."
        })

    # 3. IP Address Hostname
    if features.get("has_ip_address", 0) == 1:
        findings.append({
            "severity": "CRITICAL",
            "title": "Raw IP Address Used Instead of Domain",
            "description": "The hostname is a raw IP address (e.g. http://192.168.x.x). Legitimate web services use registered domain names. This is a common evasion technique."
        })

    # 4. Free Cloud / Subdomain Provider Abuse
    if free_cloud:
        findings.append({
            "severity": "HIGH",
            "title": "Hosted on Free Cloud / PaaS Platform",
            "description": "Site is hosted on a free hosting platform (Firebase, Workers, Vercel, Glitch). Cybercriminals frequently abuse free tiers to host disposable phishing pages."
        })

    # 5. High-Risk / Disposable TLD
    if features.get("high_risk_tld", 0) == 1:
        findings.append({
            "severity": "HIGH",
            "title": "Suspicious / High-Risk Top-Level Domain",
            "description": "The domain uses a TLD with a historically high proportion of malicious registrations (.xyz, .top, .tk, .buzz, etc.)."
        })

    # 6. Subdomain Stacking
    subdomains = features.get("count_subdomains", 0)
    if subdomains >= 3:
        findings.append({
            "severity": "HIGH",
            "title": f"Excessive Subdomain Stacking ({subdomains} subdomains)",
            "description": "Multiple subdomains were detected. Phishers concatenate multiple subdomain labels to push the real domain out of view on mobile address bars."
        })

    # 7. Suspicious Authentication Keywords
    kw_count = features.get("suspicious_keyword_count", 0)
    if kw_count >= 2:
        findings.append({
            "severity": "MEDIUM",
            "title": f"Sensitive Credential Keywords ({kw_count} keywords)",
            "description": "URL contains sensitive keywords often associated with credential harvesting (login, verify, account, secure, banking, password)."
        })

    # 8. High Shannon Entropy (Random DGA Domain)
    entropy = features.get("domain_shannon_entropy", 0.0)
    if entropy >= 3.8:
        findings.append({
            "severity": "HIGH",
            "title": f"High Character Entropy ({entropy:.2f})",
            "description": "The domain name has high randomness, characteristic of automated Domain Generation Algorithms (DGA) used by malware and phishing infrastructure."
        })

    # 9. Special Character Exploits
    if features.get("count_at_signs", 0) > 0:
        findings.append({
            "severity": "CRITICAL",
            "title": "'@' Character Obfuscation Trick",
            "description": "The '@' character in a URL treats everything before it as username credentials and directs the browser to the domain after it."
        })

    if features.get("double_slash_in_path", 0) == 1:
        findings.append({
            "severity": "MEDIUM",
            "title": "Double Slash in Path",
            "description": "Detected '//' in the URL path, commonly used in open redirect exploits."
        })

    # If completely safe
    if not findings and risk_percentage < 35:
        findings.append({
            "severity": "SAFE",
            "title": "Standard URL Structure",
            "description": "No lexical anomalies, brand spoofing, or credential harvesting patterns were detected in this URL."
        })

    # Recommendations
    if verdict == "PHISHING":
        recommendations.append("DO NOT click or enter any passwords, credit card details, or two-factor codes.")
        recommendations.append("If you arrived from an email or SMS, report the message as phishing/spam.")
        recommendations.append("If you already submitted credentials, change your password immediately on the official website.")
    elif verdict == "SUSPICIOUS":
        recommendations.append("Proceed with extreme caution. Verify the exact domain spelling in your browser address bar.")
        recommendations.append("Look for the primary domain name (the two words before the first single slash).")
        recommendations.append("Do not download files or authorize OAuth access from this address.")
    else:
        recommendations.append("The URL appears structurally legitimate.")
        recommendations.append("Always verify you are on the intended site before entering sensitive account credentials.")

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_percentage": risk_percentage,
        "phishing_probability": round(phishing_prob, 4),
        "badge_color": badge_color,
        "https_analysis": https_summary,
        "findings": findings,
        "recommendations": recommendations
    }
