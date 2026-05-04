import os
import httpx
from backend.models.email_request import AttachmentMeta, Signal

_VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"
_TIMEOUT = 5  # seconds — fail fast if VT is slow


def analyze_with_virustotal(attachments: list[AttachmentMeta]) -> tuple[int, list[Signal]]:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return 0, []

    hashes = [(a, a.sha256) for a in attachments if a.sha256]
    if not hashes:
        return 0, []

    score = 0
    signals = []

    for attachment, sha256 in hashes:
        result = _lookup(sha256, api_key)
        if result is None:
            continue

        stats = result.get("stats", {})
        engines = result.get("engines", [])
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 3:
            score += 50
            engine_sample = ", ".join(engines[:3])
            signals.append(Signal(
                type="virustotal_malicious",
                severity="high",
                description=f"'{attachment.name}' flagged as malicious by {malicious} antivirus engines on VirusTotal (e.g. {engine_sample}).",
            ))
        elif malicious >= 1 or suspicious >= 3:
            score += 25
            engine_sample = ", ".join(engines[:3]) if engines else ""
            detail = f" (e.g. {engine_sample})" if engine_sample else ""
            signals.append(Signal(
                type="virustotal_suspicious",
                severity="medium",
                description=f"'{attachment.name}' flagged as suspicious by {malicious + suspicious} antivirus engines on VirusTotal{detail}.",
            ))

    return min(score, 100), signals


def _lookup(sha256: str, api_key: str) -> dict | None:
    try:
        response = httpx.get(
            _VT_URL.format(hash=sha256),
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT,
        )
        if response.status_code == 404:
            return None  # File not in VT database — unknown, not malicious
        if response.status_code != 200:
            return None

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        malicious_engines = [
            engine for engine, r in results.items()
            if r.get("category") == "malicious"
        ]
        return {"stats": stats, "engines": malicious_engines}

    except Exception:
        return None
