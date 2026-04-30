import re

MAX_BODY_CHARS = 2000

# Common signature delimiters
_SIGNATURE_PATTERNS = [
    r"--\s*\n",
    r"^(Best regards|Kind regards|Regards|Thanks|Thank you|Cheers|Sincerely),?\s*$",
    r"^Sent from my (iPhone|Android|iPad|Samsung)",
]
_SIGNATURE_RE = re.compile("|".join(_SIGNATURE_PATTERNS), re.IGNORECASE | re.MULTILINE)


def minimize(text: str) -> str:
    """Trim signature and cap length, keeping only phishing-relevant content."""
    match = _SIGNATURE_RE.search(text)
    if match:
        text = text[: match.start()]

    return text[:MAX_BODY_CHARS].strip()
