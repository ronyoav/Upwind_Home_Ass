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
