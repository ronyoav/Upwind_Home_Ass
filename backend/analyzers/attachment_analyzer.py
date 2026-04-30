from backend.models.email_request import AttachmentMeta, Signal

_DANGEROUS_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".scr",
    ".jar", ".com", ".pif", ".msi", ".wsf", ".hta",
}

_DANGEROUS_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-executable",
    "application/javascript",
    "application/x-sh",
    "application/x-bat",
}


def analyze_attachments(attachments: list[AttachmentMeta]) -> tuple[int, list[Signal]]:
    if not attachments:
        return 0, []

    score = 0
    signals = []

    dangerous = [
        a for a in attachments
        if _is_dangerous_ext(a.name) or a.mime_type in _DANGEROUS_MIME_TYPES
    ]

    if dangerous:
        score += 35
        names = ", ".join(a.name for a in dangerous[:3])
        signals.append(Signal(
            type="dangerous_attachment",
            severity="high",
            description=f"Potentially dangerous attachment(s): {names}",
        ))

    return min(score, 100), signals


def _is_dangerous_ext(filename: str) -> bool:
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in _DANGEROUS_EXTENSIONS)
