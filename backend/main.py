import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.models.email_request import EmailAnalysisRequest, EmailAnalysisResponse
from backend.sanitizer.pipeline import sanitize
from backend.analyzers.header_analyzer import analyze_headers
from backend.analyzers.content_analyzer import analyze_content
from backend.analyzers.url_analyzer import analyze_urls
from backend.analyzers.attachment_analyzer import analyze_attachments
from backend.analyzers.virustotal_analyzer import analyze_with_virustotal
from backend.analyzers.llm_analyzer import analyze_with_llm
from backend.scoring.aggregator import aggregate

app = FastAPI(title="Malicious Email Scorer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/analyze", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    # VirusTotal runs on raw attachments before the sanitizer strips <object>/<embed> tags
    vt_score, vt_signals = analyze_with_virustotal(request.attachments)

    sanitized = sanitize(request)

    header_score, header_signals = analyze_headers(sanitized["headers"])
    content_score, content_signals = analyze_content(sanitized["body"], sanitized["subject"])
    sender_domain = None
    if sanitized["headers"].from_address:
        match = __import__("re").search(r"@([\w.\-]+)", sanitized["headers"].from_address)
        sender_domain = match.group(1).lower() if match else None

    url_score, url_signals = analyze_urls(sanitized["urls"], sanitized["link_mismatches"], sanitized["has_base64_payload"], sender_domain)
    attachment_score, attachment_signals = analyze_attachments(sanitized["attachments"])
    rule_score = min(header_score + content_score + url_score + attachment_score + vt_score, 100)
    all_rule_signals = header_signals + content_signals + url_signals + attachment_signals + vt_signals

    llm_score, explanation, llm_signals = analyze_with_llm(sanitized)

    final_score, verdict, verdict_label = aggregate(rule_score, llm_score, all_rule_signals)
    all_signals = all_rule_signals + llm_signals

    return EmailAnalysisResponse(
        score=final_score,
        verdict=verdict,
        verdict_label=verdict_label,
        explanation=explanation,
        signals=all_signals,
    )
