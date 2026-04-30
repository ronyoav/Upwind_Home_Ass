from bs4 import BeautifulSoup


def clean_html(html: str) -> str:
    """Strip scripts, styles, tracking pixels and return plain text."""
    soup = BeautifulSoup(html, "lxml")

    # Remove dangerous/tracking tags entirely
    for tag in soup.find_all(["script", "style", "noscript", "iframe", "object", "embed"]):
        tag.decompose()

    # Remove 1x1 tracking pixels
    for img in soup.find_all("img"):
        width = img.get("width", "")
        height = img.get("height", "")
        if str(width) == "1" or str(height) == "1":
            img.decompose()

    return soup.get_text(separator=" ", strip=True)
