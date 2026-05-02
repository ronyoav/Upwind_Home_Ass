import os
from backend.models.email_request import AttachmentMeta, Signal

_HIGH_RISK_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".scr",
    ".jar", ".com", ".pif", ".msi", ".wsf", ".hta", ".iso", ".img",
}

_HIGH_RISK_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-executable",
    "application/javascript",
    "application/x-sh",
    "application/x-bat",
    "application/x-iso9660-image",
}

# Office formats and PDFs can carry macros or exploits — medium risk
_MEDIUM_RISK_EXTENSIONS = {
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".pdf", ".rtf", ".one", ".pub",
}

_MEDIUM_RISK_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/rtf",
}

# Expected MIME types per extension — used to catch disguised files (e.g. invoice.pdf served as application/javascript)
_EXPECTED_MIME = {
    ".pdf":  {"application/pdf"},
    ".jpg":  {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png":  {"image/png"},
    ".gif":  {"image/gif"},
    ".txt":  {"text/plain"},
    ".zip":  {"application/zip", "application/x-zip-compressed"},
    ".doc":  {"application/msword"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".xls":  {"application/vnd.ms-excel"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    ".ppt":  {"application/vnd.ms-powerpoint"},
    ".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
}


def analyze_attachments(attachments: list[AttachmentMeta]) -> tuple[int, list[Signal]]:
    if not attachments:
        return 0, []

    score = 0
    signals = []

    high_risk = [a for a in attachments if _is_high_risk(a)]
    medium_risk = [a for a in attachments if not _is_high_risk(a) and _is_medium_risk(a)]

    if high_risk:
        score += 40
        names = ", ".join(a.name for a in high_risk[:3])
        signals.append(Signal(
            type="dangerous_attachment",
            severity="high",
            description=f"High-risk attachment(s) detected: {names}.",
        ))

    if medium_risk:
        score += 15
        names = ", ".join(a.name for a in medium_risk[:3])
        signals.append(Signal(
            type="suspicious_attachment",
            severity="medium",
            description=f"Office/PDF attachment(s) may contain macros or exploits: {names}.",
        ))

    double_ext = [a for a in attachments if _has_double_extension(a)]
    if double_ext:
        score += 40
        names = ", ".join(a.name for a in double_ext[:3])
        signals.append(Signal(
            type="double_extension",
            severity="high",
            description=f"Attachment has a dangerous hidden extension: {names} — may appear as a document but executes as code.",
        ))

    mime_mismatch = [a for a in attachments if _has_mime_mismatch(a)]
    if mime_mismatch:
        score += 35
        a = mime_mismatch[0]
        ext = os.path.splitext(a.name.lower())[1]
        signals.append(Signal(
            type="mime_mismatch",
            severity="high",
            description=f"'{a.name}' has extension '{ext}' but MIME type '{a.mime_type}' — file is not what it claims to be.",
        ))

    return min(score, 100), signals


def _is_high_risk(a: AttachmentMeta) -> bool:
    lower = a.name.lower()
    return (
        any(lower.endswith(ext) for ext in _HIGH_RISK_EXTENSIONS)
        or a.mime_type in _HIGH_RISK_MIME_TYPES
    )


def _is_medium_risk(a: AttachmentMeta) -> bool:
    lower = a.name.lower()
    return (
        any(lower.endswith(ext) for ext in _MEDIUM_RISK_EXTENSIONS)
        or a.mime_type in _MEDIUM_RISK_MIME_TYPES
    )


def _has_double_extension(a: AttachmentMeta) -> bool:
    """Catches invoice.pdf.exe — the outer extension is dangerous, inner fakes legitimacy."""
    parts = a.name.lower().split(".")
    if len(parts) < 3:
        return False
    outer_ext = "." + parts[-1]
    return outer_ext in _HIGH_RISK_EXTENSIONS


def _has_mime_mismatch(a: AttachmentMeta) -> bool:
    """Catches files where extension implies a safe type but MIME type is dangerous."""
    ext = os.path.splitext(a.name.lower())[1]
    expected = _EXPECTED_MIME.get(ext)
    if not expected:
        return False
    return a.mime_type not in expected and a.mime_type in _HIGH_RISK_MIME_TYPES
