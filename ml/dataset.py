"""
Dataset curation and loader for Phishing URL Detection.
Contains diverse, realistic, and modern samples:
- Legitimate URLs across tech, e-commerce, banking, blogs, education, deep paths
- Phishing URLs including modern HTTPS-encrypted phishing, token spoofing,
  IP hostnames, DGA domains, free cloud host abuses, and typosquatting.
"""

from typing import List, Tuple

# Representative Legitimate URLs
LEGITIMATE_SAMPLES: List[str] = [
    # Search & Tech Portals
    "https://www.google.com",
    "https://www.google.com/search?q=machine+learning+tutorial",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://drive.google.com/drive/my-drive",
    "https://www.bing.com",
    "https://www.yahoo.com/news/world",
    "https://duckduckgo.com/?q=cybersecurity+best+practices",
    
    # E-Commerce & Retail
    "https://www.amazon.com",
    "https://www.amazon.com/dp/B08N5WRWNW?ref_=cm_sw_r_cp_ud_dp",
    "https://www.amazon.co.uk/orders",
    "https://www.ebay.com/itm/123456789",
    "https://www.walmart.com/browse/electronics/computers",
    "https://www.target.com/p/apple-ipad-10-2-inch-wi-fi",
    "https://www.bestbuy.com/site/apple-macbook-pro",
    "https://www.flipkart.com/laptops-store",
    
    # Banking & Financial Institutions (Genuine)
    "https://www.chase.com",
    "https://secure07c.chase.com/web/auth/dashboard",
    "https://www.bankofamerica.com",
    "https://www.wellsfargo.com",
    "https://online.citi.com/US/login.do",
    "https://www.paypal.com/us/home",
    "https://www.paypal.com/signin",
    "https://www.stripe.com/docs/api",
    "https://www.americanexpress.com",
    
    # Cloud, Dev & Tech Platforms
    "https://github.com/scikit-learn/scikit-learn",
    "https://github.com/trending",
    "https://gitlab.com/explore",
    "https://stackoverflow.com/questions/123456/fastapi-uvicorn-routing",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
    "https://www.microsoft.com/en-us/windows",
    "https://portal.azure.com",
    "https://aws.amazon.com/console/",
    "https://cloud.google.com/docs",
    "https://pypi.org/project/scikit-learn/",
    "https://hub.docker.com/_/python",
    "https://www.digitalocean.com/community/tutorials",
    "https://medium.com/@user/cybersecurity-overview-12345",
    "https://www.reddit.com/r/MachineLearning/",
    
    # Legitimate Developer & Student Web Apps on Cloud/PaaS
    "https://fastapi-student-demo.onrender.com",
    "https://phishing-detector-project.onrender.com",
    "https://react-portfolio-app.vercel.app",
    "https://documentation-guides.netlify.app",
    "https://developer-profile.github.io/portfolio",
    "https://ai-research-demo.onrender.com/dashboard",
    
    # Social & Media
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.linkedin.com/in/profile",
    "https://twitter.com/NASA/status/1234567890",
    "https://www.instagram.com/explore/",
    "https://www.facebook.com/policies",
    "https://www.netflix.com/browse",
    "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M",
    
    # Education & Research
    "https://www.mit.edu/research/",
    "https://cs.stanford.edu/people/karpathy/",
    "https://www.ox.ac.uk/admissions",
    "https://arxiv.org/abs/2103.12345",
    "https://www.nature.com/articles/s41586-020-2649-2",
    "https://www.ncbi.nlm.nih.gov/pmc/articles/PMC1234567/",
    "https://ieee.org/conferences/schedule",
    "https://w3schools.com/python/python_ml_getting_started.asp",
    
    # HTTP legitimate legacy/mirror sites (testing that HTTP alone does not immediately equal malicious)
    "http://info.cern.ch/hypertext/WWW/TheProject.html",
    "http://www.gnu.org/licenses/gpl-3.0.html",
    "http://neverssl.com",
    "http://example.com",
    "http://www.columbia.edu/~fdc/sample.html",
    "http://archive.ubuntu.com/ubuntu/",
    "http://mirrors.kernel.org/debian/"
]

# Representative Phishing URLs
PHISHING_SAMPLES: List[str] = [
    # Modern HTTPS Phishing with Typosquatting / Brand Spoofing (CRITICAL TEST CASES)
    "https://paypa1-security-verification.com/webscr/login",
    "https://www.paypaI.com-account-update.xyz/signin",
    "https://paypal.com.account-security-alert.net/confirm",
    "https://verify-apple-id.manage-account.info/session/login.php",
    "https://netflix-billing-recovery.com/customer-service/update-card",
    "https://amazn-prime-order-verification.com/signin?ref=update",
    "https://microsoft-office365-verify.com/login/auth",
    "https://google-drive-shared-file-verify.com/view?id=987123",
    "https://faceb00k-support-security-check.com/checkpoint",
    "https://chase-security-authenticate.com/auth/logon",
    "https://wellsfargo-account-restore.com/signon",
    "https://bankofamerica-secure-login-portal.net/auth",
    "https://binance-wallet-synchronize.com/connect-wallet",
    "https://metamask-seed-phrase-verify.io/recovery",
    "https://coinbase-auth-resolve.net/security-check",

    # HTTPS Abuse on Free Cloud / PaaS Hosting (Real-world pattern)
    "https://paypal-support-login.firebaseapp.com",
    "https://bank-verification-notice.web.app/confirm",
    "https://appleid-session-expire.workers.dev/auth",
    "https://secure-update-billing.pages.dev/login",
    "https://chase-auth-service.vercel.app/verify",
    "https://onedrive-sharepoint-document.glitch.me/sign-in",
    "https://google-auth-verify.netlify.app/index.html",
    "https://account-security-center.000webhostapp.com/login.html",

    # HTTPS Token in Hostname Deception
    "http://https-paypal-login-account-update.com",
    "http://https-apple-id-verify.top/index.php",
    "https://chase.com.https-account-review.xyz/auth",
    "https://bank.com.https-secure-server.link/portal",
    "http://https-secure-banking-alert.com/login",

    # IP Address Hostnames (Dangerous Phishing Pattern)
    "http://192.168.1.105/bank/login.php",
    "http://104.244.72.115/update-account/signin.html",
    "http://185.220.101.5/paypal/verify.php?cmd=_login",
    "https://198.51.100.42:8443/chase-online/auth",
    "http://45.146.164.110/apple-security/signin",

    # High Subdomain Stacking / Obfuscation
    "http://login.verify.account.paypal.com.customer.security-alert.xyz/index.html",
    "https://chase.com.accounts.portal.security.update.warning-server.top/signon",
    "http://apple.id.manage.findmy.session.authenticate.service-cloud.ml/auth",
    "https://drive.google.com.file.preview.account.login.service-alert.club/view",

    # Obfuscated / Special Character Exploits (@ userinfo spoofing & double slashes)
    "http://www.google.com@phishing-target-site.com/login",
    "https://paypal.com@verify-credentials-now.com/secure",
    "http://chase.com//verify-login//authenticate//signin.html",
    "http://secure-update-portal.com?redirect=https://legitimate.com&stolen_data=1",

    # High Entropy / DGA Domains (Domain Generation Algorithms)
    "http://xq891zklmno-secure-banking.xyz/session",
    "https://a9x8k21mno0418-update.top/auth/verify",
    "http://qzwxecrvtbynuimo.info/login.php",
    "https://9812734918274918237-bank-service.surf/signin",

    # Suspicious Keywords + Disposable High-Risk TLDs
    "http://verify-bank-account-urgent.top/login.php",
    "https://update-security-protection.xyz/account",
    "http://account-suspended-action-required.buzz/restore",
    "https://recover-funds-wallet-secure.work/auth",
    "http://urgent-invoice-payment-overdue.fit/download.php"
]


def load_dataset() -> Tuple[List[str], List[int]]:
    """
    Returns (urls, labels) where:
    0 = Legitimate
    1 = Phishing
    """
    urls = []
    labels = []

    for url in LEGITIMATE_SAMPLES:
        urls.append(url)
        labels.append(0)

    for url in PHISHING_SAMPLES:
        urls.append(url)
        labels.append(1)

    return urls, labels
