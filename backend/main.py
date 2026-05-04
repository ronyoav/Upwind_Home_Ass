import os
import re
from concurrent.futures import ThreadPoolExecutor
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
    with ThreadPoolExecutor(max_workers=2) as ex:
        sanitize_f = ex.submit(sanitize, request)
        vt_f = ex.submit(analyze_with_virustotal, request.attachments)
    sanitized = sanitize_f.result()
    vt_score, vt_signals = vt_f.result()

    sender_domain = None
    if sanitized["headers"].from_address:
        match = re.search(r"@([\w.\-]+)", sanitized["headers"].from_address)
        sender_domain = match.group(1).lower() if match else None

    with ThreadPoolExecutor(max_workers=4) as ex:
        header_f = ex.submit(analyze_headers, sanitized["headers"])
        content_f = ex.submit(analyze_content, sanitized["body"], sanitized["subject"])
        url_f = ex.submit(analyze_urls, sanitized["urls"], sanitized["link_mismatches"], sanitized["has_base64_payload"], sender_domain)
        attachment_f = ex.submit(analyze_attachments, sanitized["attachments"])
        llm_f = ex.submit(analyze_with_llm, sanitized)

    header_score, header_signals = header_f.result()
    content_score, content_signals = content_f.result()
    url_score, url_signals = url_f.result()
    attachment_score, attachment_signals = attachment_f.result()
    llm_score, explanation, llm_signals = llm_f.result()

    rule_score = min(header_score + content_score + url_score + attachment_score + vt_score, 100)
    all_rule_signals = header_signals + content_signals + url_signals + attachment_signals + vt_signals

    final_score, verdict, verdict_label = aggregate(rule_score, llm_score, all_rule_signals)
    all_signals = all_rule_signals + llm_signals

    if any(s.type == "virustotal_malicious" for s in vt_signals):
        final_score = 100
        verdict = "dangerous"
        verdict_label = "Likely Phishing"

    return EmailAnalysisResponse(
        score=final_score,
        verdict=verdict,
        verdict_label=verdict_label,
        explanation=explanation,
        signals=all_signals,
    )
