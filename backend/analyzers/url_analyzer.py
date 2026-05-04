import re
import httpx
from urllib.parse import urlparse
from backend.models.email_request import Signal

_UNSHORTEN_TIMEOUT = 4  # seconds — fail fast

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "cutt.ly", "short.io", "is.gd", "buff.ly",
}

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".gq",
    ".ml", ".cf", ".tk", ".pw", ".cc", ".su", ".co",
}

# Keywords commonly used in phishing domains to appear legitimate
_PHISHING_KEYWORDS = re.compile(
    r"(secure|security|login|verify|verification|account|update|confirm|"
    r"drive|support|helpdesk|authenticate|validation|access|portal|signin)",
    re.IGNORECASE,
)

_IP_URL_RE = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")

_REDIRECT_PARAMS = re.compile(r"[?&](redirect|url|next|return|goto|target|dest|destination|continue)=", re.IGNORECASE)

_URL_LENGTH_THRESHOLD = 100

# Mock domain reputation DB — in production this would be a threat-intel feed.
_BAD_DOMAINS = {
    "evil.com", "phish.net", "malware-site.ru", "stealcreds.tk",
    "secure-paypal-login.xyz", "amazon-verify.top", "apple-id-locked.click",
    "microsoft-alert.work", "netflix-billing.loan", "google-security.gq",
    "update-your-account.ml", "verify-account-now.cf",
}


def analyze_urls(urls: list[str], link_mismatches: list[dict] | None = None, has_base64_payload: bool = False, sender_domain: str | None = None) -> tuple[int, list[Signal]]:
    score = 0
    signals = []

    if urls:
        # Expand shortened URLs via HEAD request before all other checks
        expanded = [_unshorten(u) if _is_shortener(u) else u for u in urls]

        shortener_urls = [u for u in urls if _is_shortener(u)]
        if shortener_urls:
            score += 15
            destinations = [e for u, e in zip(urls, expanded) if _is_shortener(u) and e != u]
            dest_hint = f" → {destinations[0]}" if destinations else ""
            signals.append(Signal(type="url_shortener", severity="medium", description=f"{len(shortener_urls)} shortened URL(s) detected{dest_hint}."))
    else:
        expanded = []

        suspicious_tld_urls = [u for u in expanded if _has_suspicious_tld(u)]
        if suspicious_tld_urls:
            score += 20
            signals.append(Signal(type="suspicious_tld", severity="high", description=f"URLs with suspicious TLDs detected: {', '.join(suspicious_tld_urls[:2])}."))

        ip_urls = [u for u in expanded if _IP_URL_RE.match(u)]
        if ip_urls:
            score += 25
            signals.append(Signal(type="ip_url", severity="high", description="URL points directly to an IP address — no legitimate domain."))

        http_urls = [u for u in expanded if u.startswith("http://")]
        if http_urls:
            score += 10
            signals.append(Signal(type="http_url", severity="low", description=f"{len(http_urls)} non-HTTPS link(s) found."))

        bad = [u for u in expanded if _is_bad_domain(u)]
        if bad:
            score += 40
            signals.append(Signal(
                type="known_bad_domain",
                severity="high",
                description=f"URL matches known malicious domain: {_extract_domain(bad[0])}.",
            ))

        keyword_domains = [u for u in expanded if _has_phishing_keywords(u)]
        if keyword_domains:
            score += 20
            example = _extract_domain(keyword_domains[0])
            signals.append(Signal(
                type="phishing_keyword_domain",
                severity="medium",
                description=f"Domain '{example}' contains keywords commonly used in phishing URLs (secure, login, verify, drive, etc.).",
            ))

        long_urls = [u for u in expanded if len(u) > _URL_LENGTH_THRESHOLD]
        if long_urls:
            score += 10
            signals.append(Signal(
                type="long_url",
                severity="low",
                description=f"Unusually long URL detected ({len(long_urls[0])} chars) — may indicate obfuscation.",
            ))

        redirect_urls = [u for u in expanded if _REDIRECT_PARAMS.search(u)]
        if redirect_urls:
            score += 15
            signals.append(Signal(
                type="redirect_param",
                severity="medium",
                description="URL contains redirect parameter (redirect=, url=, next=) — final destination may be hidden.",
            ))

    if sender_domain and expanded:
        external = [u for u in expanded if _is_external_to_sender(u, sender_domain)]
        if external:
            score += 15
            signals.append(Signal(
                type="external_domain",
                severity="medium",
                description=f"Email from '{sender_domain}' contains links pointing to unrelated external domains.",
            ))

    if has_base64_payload:
        score += 30
        signals.append(Signal(
            type="base64_payload",
            severity="high",
            description="HTML contains suspicious base64-encoded content — a technique used to hide malicious scripts from filters.",
        ))

    if link_mismatches:
        score += 30
        example = link_mismatches[0]
        signals.append(Signal(
            type="link_text_mismatch",
            severity="high",
            description=(
                f"Link displays '{example['display']}' but points to '{example['actual']}' "
                f"({len(link_mismatches)} mismatch(es) found)."
            ),
        ))

    return min(score, 100), signals


def _is_shortener(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower().lstrip("www.")
        return host in _SHORTENERS
    except Exception:
        return False


def _has_suspicious_tld(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
        return any(host.endswith(tld) for tld in _SUSPICIOUS_TLDS)
    except Exception:
        return False


def _is_bad_domain(url: str) -> bool:
    domain = _extract_domain(url)
    return domain in _BAD_DOMAINS if domain else False


def _has_phishing_keywords(url: str) -> bool:
    domain = _extract_domain(url)
    return bool(_PHISHING_KEYWORDS.search(domain)) if domain else False


def _is_external_to_sender(url: str, sender_domain: str) -> bool:
    url_domain = _extract_domain(url)
    if not url_domain:
        return False
    sender_root = ".".join(sender_domain.split(".")[-2:])
    url_root = ".".join(url_domain.split(".")[-2:])
    return url_root != sender_root


def _extract_domain(url: str) -> str | None:
    try:
        return urlparse(url).netloc.lower().lstrip("www.") or None
    except Exception:
        return None


def _unshorten(url: str) -> str:
    """Follow redirects via HEAD request and return the final destination URL."""
    try:
        r = httpx.head(url, follow_redirects=True, timeout=_UNSHORTEN_TIMEOUT)
        final = str(r.url)
        return final if final != url else url
    except Exception:
        return url
