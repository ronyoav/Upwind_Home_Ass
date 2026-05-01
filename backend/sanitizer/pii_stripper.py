import re

# Common prompt-injection phrases found in adversarial emails.
# These are replaced before content reaches the LLM.
_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context|rules?)|"
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context|rules?)|"
    r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)|"
    r"you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another|unrestricted)|"
    r"new\s+instructions?\s*:|"
    r"system\s+prompt\s*:|"
    r"respond\s+with\s+text\s+only|"
    r"do\s+not\s+call\s+any\s+tools?|"
    r"override\s+(your\s+)?(previous\s+)?(instructions?|rules?|behavior)|"
    r"act\s+as\s+(?:if\s+)?(?:you\s+(?:have\s+no|are\s+without)\s+restrictions?)|"
    r"jailbreak|"
    r"DAN\s+mode|"
    r"your\s+true\s+self)",
    re.IGNORECASE,
)

# Intentionally keep email addresses and domains — they are phishing signals.
_PATTERNS = [
    (r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", "[CREDIT_CARD]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
    (r"\b(\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b", "[PHONE_NUMBER]"),
    # Israeli phone numbers: 05X-XXXXXXX
    (r"\b0[5-9]\d[\-\s]?\d{7}\b", "[PHONE_NUMBER]"),
    # Israeli ID (9 digits) — must come after credit card to avoid overlap
    (r"\b\d{9}\b", "[ID_NUMBER]"),
    # Street addresses: "123 Main St", "456 Elm Avenue"
    (r"\b\d{1,5}\s+[A-Za-z0-9\s]{3,40}(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b", "[PHYSICAL_ADDRESS]"),
]


# Query parameters commonly used to carry PII in tracking URLs
_PII_PARAMS = re.compile(
    r"([?&])(email|mail|user|name|fname|lname|first_name|last_name|recipient|uid|userid|user_id|contact)=[^&]*",
    re.IGNORECASE,
)


def strip_url_pii(url: str) -> str:
    """Remove known PII query parameters from a URL."""
    return _PII_PARAMS.sub(r"\1\2=[REDACTED]", url)


def strip_prompt_injection(text: str) -> str:
    """Replace known prompt-injection phrases so they cannot hijack the LLM."""
    return _INJECTION_PATTERNS.sub("[INJECTION_ATTEMPT_REDACTED]", text)


def strip_pii(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text
