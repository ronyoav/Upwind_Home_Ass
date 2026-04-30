import re

# Intentionally keep email addresses and domains — they are phishing signals.
_PATTERNS = [
    (r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", "[CREDIT_CARD]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
    (r"\b(\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b", "[PHONE_NUMBER]"),
    # Street addresses: "123 Main St", "456 Elm Avenue"
    (r"\b\d{1,5}\s+[A-Za-z0-9\s]{3,40}(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b", "[PHYSICAL_ADDRESS]"),
]


def strip_pii(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text
