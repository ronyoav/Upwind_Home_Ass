import json
import os
import anthropic
from backend.models.email_request import Signal

_CLIENT = None


def _get_client() -> anthropic.Anthropic:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = anthropic.Anthropic(api_key=os.environ["API_KEY_CLAUDE"])
    return _CLIENT


_SYSTEM_PROMPT = """You are a cybersecurity expert specializing in phishing email detection.
Analyze the provided email data and return a JSON object with this exact structure:
{
  "phishing_score": <integer 0-100>,
  "detected_tactics": [<list of short tactic names>],
  "explanation": "<2-3 sentence explanation in English for a non-technical user>",
  "confidence": "<high|medium|low>"
}

Score guide:
- 0-30: Likely legitimate
- 31-60: Suspicious, warrants caution
- 61-100: Likely phishing or malicious

Be concise, accurate, and always respond in English only. Return valid JSON only, no markdown."""


def analyze_with_llm(sanitized: dict) -> tuple[int, str, list[Signal]]:
    """Returns (llm_score 0-100, explanation, signals)."""
    prompt = _build_prompt(sanitized)

    try:
        response = _get_client().messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        data = json.loads(raw)

        llm_score = int(data.get("phishing_score", 0))
        explanation = data.get("explanation", "No explanation provided.")
        tactics = data.get("detected_tactics", [])

        signals = []
        if tactics:
            signals.append(Signal(
                type="llm_tactics_detected",
                severity="high" if llm_score >= 60 else "medium",
                description=f"AI detected tactics: {', '.join(tactics)}.",
            ))

        return llm_score, explanation, signals

    except (json.JSONDecodeError, KeyError, anthropic.APIError) as exc:
        # Fail open — return neutral score, no signals
        return 0, f"AI analysis unavailable: {type(exc).__name__}.", []


def _build_prompt(sanitized: dict) -> str:
    urls_text = "\n".join(sanitized["urls"][:20]) if sanitized["urls"] else "None"
    attachments_text = (
        ", ".join(f"{a.name} ({a.mime_type})" for a in sanitized["attachments"][:5])
        if sanitized["attachments"] else "None"
    )
    headers = sanitized["headers"]

    return f"""Analyze this email for phishing indicators:

Subject: {sanitized['subject']}
From: {headers.from_address or 'Unknown'}
Reply-To: {headers.reply_to or 'Same as From'}
SPF: {headers.spf or 'Unknown'}
DKIM: {headers.dkim or 'Unknown'}
DMARC: {headers.dmarc or 'Unknown'}

Body (sanitized):
{sanitized['body'] or '(empty)'}

URLs found:
{urls_text}

Attachments:
{attachments_text}"""
