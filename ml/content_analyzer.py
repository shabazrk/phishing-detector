"""
Website Content & Redirect Chain Analyzer for AI Phishing Detection.
Safely inspects HTTP redirect chains, SSL/TLS certificates, and HTML DOM
features (forms, password fields, iframes, favicons, title-brand mismatches)
without executing JavaScript or probing internal/private networks (SSRF-safe).
"""

import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .features import TARGET_BRANDS, sanitize_url

MAX_REDIRECTS = 10
REQUEST_TIMEOUT = 6
MAX_HTML_BYTES = 512 * 1024  # 512 KB cap for safety


def _get_registered_domain(hostname: str) -> str:
    """Extracts an approximate registered domain (e.g. 'sub.paypal.com' -> 'paypal.com')."""
    host = (hostname or "").lower().split(":")[0]
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _is_safe_public_host(hostname: str) -> Tuple[bool, str]:
    """
    Validates that the hostname does not resolve to a private, loopback,
    or reserved IP address (SSRF protection).
    """
    if not hostname:
        return False, "Empty hostname"

    if hostname.lower() in ("localhost", "localhost.localdomain"):
        return False, "Localhost is blocked for live fetch"

    try:
        # Check if hostname is already an IP literal
        ip_obj = ipaddress.ip_address(hostname)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        ):
            return False, f"Private/reserved IP ({hostname}) skipped"
        return True, ""
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                return False, f"Resolves to private/reserved IP ({ip_str})"
        return True, ""
    except socket.gaierror:
        return False, "Domain could not be resolved (DNS lookup failed)"
    except Exception as exc:
        return False, f"Host validation failed: {exc}"


class _RedirectTracker(urllib.request.HTTPRedirectHandler):
    """Tracks every HTTP redirect hop safely."""

    def __init__(self):
        super().__init__()
        self.hops: List[Dict[str, Any]] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if len(self.hops) >= MAX_REDIRECTS:
            return None

        resolved_new_url = urljoin(req.full_url, newurl)
        from_host = urlparse(req.full_url).hostname or ""
        to_host = urlparse(resolved_new_url).hostname or ""

        safe, reason = _is_safe_public_host(to_host)
        if not safe:
            self.hops.append({
                "step": len(self.hops) + 1,
                "status_code": code,
                "from_url": req.full_url,
                "to_url": resolved_new_url,
                "cross_domain": _get_registered_domain(from_host) != _get_registered_domain(to_host),
                "https_downgrade": req.full_url.startswith("https://") and resolved_new_url.startswith("http://"),
                "blocked_reason": reason,
            })
            return None

        self.hops.append({
            "step": len(self.hops) + 1,
            "status_code": code,
            "from_url": req.full_url,
            "to_url": resolved_new_url,
            "cross_domain": _get_registered_domain(from_host) != _get_registered_domain(to_host),
            "https_downgrade": req.full_url.startswith("https://") and resolved_new_url.startswith("http://"),
            "blocked_reason": None,
        })
        return super().redirect_request(req, fp, code, msg, headers, resolved_new_url)


class _WebsiteHTMLParser(HTMLParser):
    """Lightweight HTML parser extracting phishing-relevant DOM features."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.base_domain = _get_registered_domain(urlparse(base_url).hostname or "")
        self.in_title = False
        self.title_parts: List[str] = []

        self.form_count = 0
        self.external_form_actions: List[str] = []
        self.insecure_form_actions: List[str] = []
        self.has_password_field = False
        self.input_count = 0

        self.iframe_count = 0
        self.hidden_iframe_count = 0

        self.total_links = 0
        self.external_links = 0
        self.total_scripts = 0
        self.external_scripts = 0

        self.favicon_external = False
        self.favicon_url: Optional[str] = None
        self.meta_refresh_url: Optional[str] = None
        self.right_click_disabled = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        # Check right-click disabling anywhere
        oncontext = attr_dict.get("oncontextmenu", "").lower()
        if "return false" in oncontext or "preventdefault" in oncontext:
            self.right_click_disabled = True

        if tag == "title":
            self.in_title = True

        elif tag == "form":
            self.form_count += 1
            action = attr_dict.get("action", "").strip()
            if action and not action.startswith("#") and not action.lower().startswith("javascript:"):
                resolved = urljoin(self.base_url, action)
                parsed_act = urlparse(resolved)
                act_domain = _get_registered_domain(parsed_act.hostname or "")
                if act_domain and act_domain != self.base_domain:
                    self.external_form_actions.append(resolved)
                if parsed_act.scheme.lower() == "http":
                    self.insecure_form_actions.append(resolved)

        elif tag == "input":
            self.input_count += 1
            input_type = attr_dict.get("type", "text").lower()
            if input_type == "password":
                self.has_password_field = True

        elif tag == "iframe":
            self.iframe_count += 1
            style = attr_dict.get("style", "").lower().replace(" ", "")
            width = attr_dict.get("width", "").strip()
            height = attr_dict.get("height", "").strip()
            if (
                width == "0"
                or height == "0"
                or "display:none" in style
                or "visibility:hidden" in style
            ):
                self.hidden_iframe_count += 1

        elif tag == "a":
            href = attr_dict.get("href", "").strip()
            if href and not href.startswith("#") and not href.lower().startswith("javascript:"):
                self.total_links += 1
                resolved = urljoin(self.base_url, href)
                link_domain = _get_registered_domain(urlparse(resolved).hostname or "")
                if link_domain and link_domain != self.base_domain:
                    self.external_links += 1

        elif tag == "script":
            self.total_scripts += 1
            src = attr_dict.get("src", "").strip()
            if src:
                resolved = urljoin(self.base_url, src)
                script_domain = _get_registered_domain(urlparse(resolved).hostname or "")
                if script_domain and script_domain != self.base_domain:
                    self.external_scripts += 1

        elif tag == "link":
            rel = attr_dict.get("rel", "").lower()
            if "icon" in rel:
                href = attr_dict.get("href", "").strip()
                if href:
                    resolved = urljoin(self.base_url, href)
                    self.favicon_url = resolved
                    fav_domain = _get_registered_domain(urlparse(resolved).hostname or "")
                    if fav_domain and fav_domain != self.base_domain:
                        self.favicon_external = True

        elif tag == "meta":
            http_equiv = attr_dict.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                content = attr_dict.get("content", "")
                match = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.IGNORECASE)
                if match:
                    self.meta_refresh_url = urljoin(self.base_url, match.group(1))

    def handle_endtag(self, tag: str):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str):
        if self.in_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split()).strip()


def _inspect_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Fetches basic SSL/TLS certificate metadata without trusting invalid certs blindly."""
    if not hostname:
        return {"available": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                return {
                    "available": True,
                    "valid": True,
                    "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA",
                    "subject_cn": subject.get("commonName", hostname),
                    "expires": cert.get("notAfter", "Unknown"),
                }
    except ssl.SSLCertVerificationError as exc:
        return {
            "available": True,
            "valid": False,
            "issuer": "Unverified / Self-Signed",
            "error": str(exc),
        }
    except Exception:
        return {"available": False}


def analyze_website_and_redirects(raw_url: str) -> Dict[str, Any]:
    """
    Performs safe live HTTP redirect tracking, SSL inspection, and HTML content analysis.
    Returns structured redirect_analysis and content_analysis dictionaries.
    """
    start_url = sanitize_url(raw_url)
    parsed_start = urlparse(start_url)
    start_host = (parsed_start.hostname or "").lower()

    safe, reason = _is_safe_public_host(start_host)
    if not safe:
        return {
            "fetched": False,
            "fetch_status": "skipped",
            "fetch_message": reason,
            "redirect_analysis": {
                "initial_url": start_url,
                "final_url": start_url,
                "redirect_count": 0,
                "hops": [],
                "cross_domain_redirect": False,
                "https_downgrade": False,
                "meta_refresh_url": None,
                "safety_score": 100 if not parsed_start.scheme == "http" else 75,
                "safety_verdict": "NOT FETCHED",
                "summary": f"Live redirect check skipped ({reason}).",
            },
            "content_analysis": {
                "available": False,
                "reason": reason,
            },
        }

    tracker = _RedirectTracker()
    opener = urllib.request.build_opener(tracker)
    opener.addheaders = [
        ("User-Agent", "Mozilla/5.0 (compatible; PhishGuardAI/1.0; SecurityScanner)")
    ]

    final_url = start_url
    status_code = None
    html_text = ""
    content_type = ""
    fetch_error = None

    try:
        with opener.open(start_url, timeout=REQUEST_TIMEOUT) as resp:
            final_url = resp.geturl()
            status_code = resp.getcode()
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" in content_type.lower() or "application/xhtml" in content_type.lower() or not content_type:
                raw_bytes = resp.read(MAX_HTML_BYTES)
                html_text = raw_bytes.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        final_url = exc.geturl() or start_url
        status_code = exc.code
        try:
            raw_bytes = exc.read(MAX_HTML_BYTES)
            html_text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception as exc:
        fetch_error = str(exc)

    hops = tracker.hops
    redirect_count = len(hops)
    cross_domain_redirect = any(h["cross_domain"] for h in hops)
    https_downgrade = any(h["https_downgrade"] for h in hops)

    # Parse HTML content if retrieved
    parsed_final = urlparse(final_url)
    final_host = (parsed_final.hostname or "").lower()
    final_reg_domain = _get_registered_domain(final_host)

    content_data: Dict[str, Any] = {"available": False}
    meta_refresh_url = None

    if html_text:
        parser = _WebsiteHTMLParser(final_url)
        try:
            parser.feed(html_text)
        except Exception:
            pass

        meta_refresh_url = parser.meta_refresh_url
        if meta_refresh_url:
            meta_domain = _get_registered_domain(urlparse(meta_refresh_url).hostname or "")
            if meta_domain and meta_domain != final_reg_domain:
                cross_domain_redirect = True

        # Check title vs domain brand mismatch
        title_lower = parser.title.lower()
        title_brand_mismatch = False
        matched_title_brand = None
        for brand in TARGET_BRANDS:
            if brand in title_lower and brand not in final_host:
                title_brand_mismatch = True
                matched_title_brand = brand
                break

        external_link_ratio = round(
            parser.external_links / max(1, parser.total_links), 2
        )

        # SSL info if HTTPS
        ssl_info = (
            _inspect_ssl_certificate(final_host, parsed_final.port or 443)
            if parsed_final.scheme.lower() == "https"
            else {"available": False}
        )

        content_data = {
            "available": True,
            "http_status": status_code,
            "page_title": parser.title or "(No Title)",
            "title_brand_mismatch": title_brand_mismatch,
            "matched_title_brand": matched_title_brand,
            "form_count": parser.form_count,
            "has_password_field": parser.has_password_field,
            "input_count": parser.input_count,
            "external_form_actions": parser.external_form_actions,
            "insecure_form_actions": parser.insecure_form_actions,
            "iframe_count": parser.iframe_count,
            "hidden_iframe_count": parser.hidden_iframe_count,
            "total_links": parser.total_links,
            "external_links": parser.external_links,
            "external_link_ratio": external_link_ratio,
            "total_scripts": parser.total_scripts,
            "external_scripts": parser.external_scripts,
            "favicon_external": parser.favicon_external,
            "right_click_disabled": parser.right_click_disabled,
            "ssl_certificate": ssl_info,
        }
    elif fetch_error:
        content_data = {"available": False, "reason": fetch_error}

    # Calculate Redirect Safety Score (100 = completely safe, 0 = dangerous)
    redirect_safety_score = 100
    if https_downgrade:
        redirect_safety_score -= 50
    if cross_domain_redirect:
        redirect_safety_score -= 30
    if redirect_count >= 3:
        redirect_safety_score -= 20
    elif redirect_count >= 1:
        redirect_safety_score -= 5
    if meta_refresh_url:
        redirect_safety_score -= 25
    redirect_safety_score = max(0, redirect_safety_score)

    if redirect_count == 0 and not meta_refresh_url:
        redirect_verdict = "NO REDIRECTS"
        redirect_summary = "URL resolves directly with no HTTP or HTML redirects."
    elif redirect_safety_score >= 75:
        redirect_verdict = "SAFE REDIRECT"
        redirect_summary = f"Followed {redirect_count} redirect(s) within expected safe bounds."
    elif redirect_safety_score >= 45:
        redirect_verdict = "SUSPICIOUS REDIRECT"
        redirect_summary = "Cross-domain or multi-hop redirect detected. Verify the final destination."
    else:
        redirect_verdict = "DANGEROUS REDIRECT"
        redirect_summary = "High-risk redirect behavior detected (HTTPS downgrade, cross-domain jump, or hidden meta refresh)."

    return {
        "fetched": fetch_error is None,
        "fetch_status": "success" if fetch_error is None else "error",
        "fetch_message": fetch_error or "Website fetched and inspected safely.",
        "redirect_analysis": {
            "initial_url": start_url,
            "final_url": final_url,
            "redirect_count": redirect_count,
            "hops": hops,
            "cross_domain_redirect": cross_domain_redirect,
            "https_downgrade": https_downgrade,
            "meta_refresh_url": meta_refresh_url,
            "safety_score": redirect_safety_score,
            "safety_verdict": redirect_verdict,
            "summary": redirect_summary,
        },
        "content_analysis": content_data,
    }
