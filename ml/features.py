"""
URL Feature Extraction Engine for AI Phishing Detection.
Extracts 25 lexical, structural, and network security features.
Includes dedicated logic addressing modern HTTPS abuse and typosquatting.
"""

import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List

# List of major brand names commonly targeted for phishing/typosquatting
TARGET_BRANDS = [
    "google", "paypal", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "twitter", "linkedin",
    "chase", "wellsfargo", "bankofamerica", "citibank", "dropbox",
    "binance", "coinbase", "metamask", "steam", "adobe", "yahoo"
]

# High risk TLDs frequently abused in disposable/free phishing campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work",
    "fit", "surf", "cn", "ru", "icu", "club", "live", "vip", "link"
}

# Free cloud hosting / PaaS domains often targeted for disposable credential phishing
FREE_CLOUD_DOMAINS = [
    "firebaseapp.com", "web.app", "workers.dev", "pages.dev",
    "glitch.me", "000webhostapp.com"
]

# Common URL shortening domains
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "tiny.cc"
}

# Suspicious keywords commonly seen in phishing paths/hostnames
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "update", "banking",
    "secure", "security", "webscr", "signin", "sign-in", "confirm",
    "confirmation", "password", "authenticate", "wallet", "support",
    "billing", "invoice", "ebayisapi", "authorise", "recover"
]

IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon Entropy of a string to detect random DGA domains."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def check_typosquatting(domain: str) -> int:
    """
    Checks if domain has a typosquatting resemblance to a protected brand.
    Returns 1 if suspiciously close (distance 1 or 2) to a brand name without being the brand.
    """
    clean_domain = domain.lower()
    # Remove port or www
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]
    parts = clean_domain.split(".")
    primary_label = parts[0] if parts else clean_domain

    for brand in TARGET_BRANDS:
        # If it contains brand + hyphen/keyword (e.g. paypal-security, login-google)
        if brand in primary_label and primary_label != brand:
            return 1
        # Edit distance 1 or 2 (e.g. paypa1, gooogle, netf1ix)
        dist = levenshtein_distance(primary_label, brand)
        if 1 <= dist <= 2 and abs(len(primary_label) - len(brand)) <= 2:
            return 1
    return 0


def sanitize_url(raw_url: str) -> str:
    """Ensures URL has a scheme for accurate parsing."""
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        # Default to http:// for lexical analysis if scheme omitted
        url = "http://" + url
    return url


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts all 25 features from a given URL string.
    Returns a dictionary of feature names and numeric values.
    """
    url = sanitize_url(raw_url)
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    netloc = parsed.netloc.lower()

    # 1. Structural Lengths
    url_length = len(raw_url)
    domain_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # 2. Character Counts
    count_dots = raw_url.count(".")
    count_hyphens = raw_url.count("-")
    count_underscores = raw_url.count("_")
    count_slashes = raw_url.count("/")
    count_question_marks = raw_url.count("?")
    count_equal_signs = raw_url.count("=")
    count_at_signs = raw_url.count("@")
    
    # Digit ratio in entire URL
    digits_count = sum(c.isdigit() for c in raw_url)
    digit_ratio = round(digits_count / max(1, url_length), 4)

    # 3. Subdomain analysis
    host_parts = hostname.split(".")
    # If host has at least 2 parts (domain.tld), count subdomains before registered domain
    if len(host_parts) > 2:
        # Subtract domain and tld (approximation)
        subdomains = host_parts[:-2]
        count_subdomains = len([s for s in subdomains if s != "www"])
    else:
        count_subdomains = 0

    # 4. IP address detection in hostname
    has_ip_address = 1 if IPV4_REGEX.match(hostname) else 0

    # 5. HTTPS Specific Features & Exploits
    is_https = 1 if scheme == "https" else 0
    
    # Does 'https' or 'ssl' appear as a deceptive string inside the hostname/subdomain?
    # e.g., 'https-login.com' or 'bank.com.https-verify.net'
    https_token_in_hostname = 1 if ("https" in hostname or "ssl" in hostname) else 0

    # Protocol mismatch: 'https' in the URL text, but protocol scheme is actually insecure 'http'
    https_http_protocol_mismatch = 1 if (scheme == "http" and "https" in raw_url.lower()) else 0

    # 6. URL Shortening Services
    has_shortener = 1 if any(shortener in hostname for shortener in SHORTENING_SERVICES) else 0

    # 7. Suspicious Keywords Count
    combined_url_lower = raw_url.lower()
    suspicious_keyword_count = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in combined_url_lower
    )

    # 8. Shannon Entropy of Domain (DGA detection)
    domain_shannon_entropy = calculate_shannon_entropy(hostname)

    # 9. Non-standard Port Specification
    has_non_standard_port = 0
    if parsed.port and parsed.port not in (80, 443):
        has_non_standard_port = 1

    # 10. High-Risk TLD Detection
    tld = host_parts[-1] if host_parts else ""
    high_risk_tld = 1 if tld in HIGH_RISK_TLDS else 0

    # 11. Free Cloud Hosting / PaaS provider check (exact domain or subdomain)
    free_cloud_host = 1 if any(hostname == domain or hostname.endswith("." + domain) for domain in FREE_CLOUD_DOMAINS) else 0

    # 12. Typosquatting / Brand Imitation Risk
    typosquatting_risk = check_typosquatting(hostname)

    # 13. Redirection Double Slash in Path
    double_slash_in_path = 1 if "//" in path else 0

    # 14. HTTPS with Suspicious Indicators (Interaction Feature)
    # Catches modern HTTPS phishing: valid SSL used with free cloud host AND keywords, or typosquatting
    https_with_suspicious_features = 1 if (
        is_https == 1 and (
            (free_cloud_host == 1 and (suspicious_keyword_count >= 1 or typosquatting_risk == 1)) or
            (high_risk_tld == 1 and suspicious_keyword_count >= 1) or
            suspicious_keyword_count >= 2 or
            typosquatting_risk == 1
        )
    ) else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_underscores": count_underscores,
        "count_slashes": count_slashes,
        "count_question_marks": count_question_marks,
        "count_equal_signs": count_equal_signs,
        "count_at_signs": count_at_signs,
        "digit_ratio": digit_ratio,
        "count_subdomains": count_subdomains,
        "has_ip_address": has_ip_address,
        "is_https": is_https,
        "https_token_in_hostname": https_token_in_hostname,
        "https_http_protocol_mismatch": https_http_protocol_mismatch,
        "has_shortener": has_shortener,
        "suspicious_keyword_count": suspicious_keyword_count,
        "domain_shannon_entropy": domain_shannon_entropy,
        "has_non_standard_port": has_non_standard_port,
        "high_risk_tld": high_risk_tld,
        "free_cloud_host": free_cloud_host,
        "typosquatting_risk": typosquatting_risk,
        "double_slash_in_path": double_slash_in_path,
        "https_with_suspicious_features": https_with_suspicious_features
    }


FEATURE_NAMES = list(extract_features("https://example.com").keys())
