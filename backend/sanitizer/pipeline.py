from .html_cleaner import clean_html, extract_link_mismatches
from .pii_stripper import strip_pii, strip_url_pii, strip_prompt_injection
from .content_minimizer import minimize
from backend.models.email_request import EmailAnalysisRequest


def sanitize(request: EmailAnalysisRequest) -> dict:
    """
    Returns a sanitized dict safe to pass to analyzers and LLM.
    HTML → plain text → PII stripped → truncated.
    URLs: PII query params redacted.
    """
    raw_text = request.body_text or ""
    link_mismatches = []
    if request.body_html:
        raw_text = clean_html(request.body_html)
        link_mismatches = extract_link_mismatches(request.body_html)

    clean_text = minimize(strip_prompt_injection(strip_pii(raw_text)))
    clean_subject = strip_prompt_injection(strip_pii(request.subject))
    clean_urls = [strip_url_pii(url) for url in request.urls]

    return {
        "message_id": request.message_id,
        "subject": clean_subject,
        "headers": request.headers,
        "body": clean_text,
        "urls": clean_urls,
        "attachments": request.attachments,
        "link_mismatches": link_mismatches,
    }
