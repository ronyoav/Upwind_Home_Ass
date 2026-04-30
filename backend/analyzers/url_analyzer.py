import re
from urllib.parse import urlparse
from backend.models.email_request import Signal

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "cutt.ly", "short.io", "is.gd", "buff.ly",
}

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".gq",
    ".ml", ".cf", ".tk", ".pw", ".cc", ".su",
}

_IP_URL_RE = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")


def analyze_urls(urls: list[str]) -> tuple[int, list[Signal]]:
    if not urls:
        return 0, []

    score = 0
    signals = []

    shortener_urls = [u for u in urls if _is_shortener(u)]
    if shortener_urls:
        score += 15
        signals.append(Signal(type="url_shortener", severity="medium", description=f"{len(shortener_urls)} shortened URL(s) detected — destination is hidden."))

    suspicious_tld_urls = [u for u in urls if _has_suspicious_tld(u)]
    if suspicious_tld_urls:
        score += 20
        signals.append(Signal(type="suspicious_tld", severity="high", description=f"URLs with suspicious TLDs detected: {', '.join(suspicious_tld_urls[:2])}."))

    ip_urls = [u for u in urls if _IP_URL_RE.match(u)]
    if ip_urls:
        score += 25
        signals.append(Signal(type="ip_url", severity="high", description="URL points directly to an IP address — no legitimate domain."))

    http_urls = [u for u in urls if u.startswith("http://")]
    if http_urls:
        score += 10
        signals.append(Signal(type="http_url", severity="low", description=f"{len(http_urls)} non-HTTPS link(s) found."))

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
