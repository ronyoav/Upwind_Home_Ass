from .html_cleaner import clean_html
from .pii_stripper import strip_pii
from .content_minimizer import minimize
from backend.models.email_request import EmailAnalysisRequest


def sanitize(request: EmailAnalysisRequest) -> dict:
    """
    Returns a sanitized dict safe to pass to analyzers and LLM.
    HTML → plain text → PII stripped → truncated.
    """
    raw_text = request.body_text or ""
    if request.body_html:
        raw_text = clean_html(request.body_html)

    clean_text = minimize(strip_pii(raw_text))
    clean_subject = strip_pii(request.subject)

    return {
        "message_id": request.message_id,
        "subject": clean_subject,
        "headers": request.headers,
        "body": clean_text,
        "urls": request.urls,
        "attachments": request.attachments,
    }
