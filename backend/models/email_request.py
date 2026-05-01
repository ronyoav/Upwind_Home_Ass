from pydantic import BaseModel
from typing import Optional


class EmailHeaders(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    from_address: Optional[str] = None
    reply_to: Optional[str] = None
    received_from: Optional[str] = None


class AttachmentMeta(BaseModel):
    name: str
    mime_type: str
    sha256: Optional[str] = None


class EmailAnalysisRequest(BaseModel):
    message_id: str
    subject: str
    headers: EmailHeaders
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    urls: list[str] = []
    attachments: list[AttachmentMeta] = []


class Signal(BaseModel):
    type: str
    severity: str  # "high" | "medium" | "low"
    description: str


class EmailAnalysisResponse(BaseModel):
    score: int  # 0-100
    verdict: str  # "safe" | "suspicious" | "dangerous"
    verdict_label: str  # "Safe" | "Suspicious" | "Likely Phishing"
    explanation: str
    signals: list[Signal]
