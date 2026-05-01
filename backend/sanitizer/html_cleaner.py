import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

_URL_LIKE = re.compile(r"^https?://|^www\.", re.IGNORECASE)


def clean_html(html: str) -> str:
    """Strip scripts, styles, tracking pixels and return plain text."""
    soup = BeautifulSoup(html, "lxml")

    for tag in soup.find_all(["script", "style", "noscript", "iframe", "object", "embed"]):
        tag.decompose()

    for img in soup.find_all("img"):
        width = img.get("width", "")
        height = img.get("height", "")
        if str(width) == "1" or str(height) == "1":
            img.decompose()

    return soup.get_text(separator=" ", strip=True)


def extract_link_mismatches(html: str) -> list[dict]:
    """
    Return anchor tags where the visible text looks like a URL but the
    actual href points to a different domain — a classic phishing trick.
    e.g. <a href="evil.xyz">paypal.com</a>
    """
    if not html:
        return []

    soup = BeautifulSoup(html, "lxml")
    mismatches = []

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        text = a.get_text(strip=True)

        if not href.startswith("http") or not _URL_LIKE.match(text):
            continue

        try:
            href_domain = urlparse(href).netloc.lower().lstrip("www.")
            text_domain = urlparse(text if text.startswith("http") else "http://" + text).netloc.lower().lstrip("www.")
        except Exception:
            continue

        if href_domain and text_domain and href_domain != text_domain:
            mismatches.append({"display": text_domain, "actual": href_domain})

    return mismatches
