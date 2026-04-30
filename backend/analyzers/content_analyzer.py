import re
from backend.models.email_request import Signal

_URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bright away\b",
    r"\blimited time\b", r"\bone.time offer\b", r"\bexpires (today|soon|in \d+ hours?)\b",
    r"\blast chance\b", r"\bdon'?t (wait|delay|miss)\b", r"\bwithin \d+ hours?\b",
    r"\bdeadline\b", r"\bfinal notice\b", r"\baction required\b",
]

_CREDENTIAL_PATTERNS = [
    r"\bverify your (account|identity|email|password|information)\b",
    r"\bconfirm your (account|identity|email|password|information)\b",
    r"\bupdate your (payment|billing|card|account)\b",
    r"\benter your (password|credentials|pin|ssn|social security)\b",
    r"\bsign in to (secure|verify|confirm)\b",
    r"\byour account (has been|will be) (suspended|locked|closed|terminated)\b",
    r"\bunusual (activity|sign.in|login) detected\b",
]

_FINANCIAL_PATTERNS = [
    r"\bwire transfer\b", r"\bgift card\b", r"\bitunes card\b", r"\bgoogle play card\b",
    r"\bcryptocurrency\b", r"\bbitcoin\b", r"\bsend money\b",
    r"\byou (have won|are selected|are a winner|won a prize)\b",
    r"\bclaim your (prize|reward|refund|money)\b",
    r"\blottery\b", r"\binheritance\b",
]

_THREAT_PATTERNS = [
    r"\byour account will be (deleted|terminated|suspended|closed)\b",
    r"\bfailure to (respond|act|verify)\b",
    r"\blegal action\b", r"\blaw enforcement\b",
    r"\bpermanently (disabled|banned|suspended)\b",
]


def analyze_content(body: str, subject: str) -> tuple[int, list[Signal]]:
    text = f"{subject} {body}".lower()
    score = 0
    signals = []

    urgency_hits = _count_matches(text, _URGENCY_PATTERNS)
    if urgency_hits >= 3:
        score += 20
        signals.append(Signal(type="urgency_language", severity="high", description=f"Strong urgency language detected ({urgency_hits} patterns)."))
    elif urgency_hits >= 1:
        score += 10
        signals.append(Signal(type="urgency_language", severity="medium", description="Urgency language detected."))

    cred_hits = _count_matches(text, _CREDENTIAL_PATTERNS)
    if cred_hits >= 1:
        score += 25
        signals.append(Signal(type="credential_phishing", severity="high", description="Email requests account credentials or personal verification."))

    fin_hits = _count_matches(text, _FINANCIAL_PATTERNS)
    if fin_hits >= 1:
        score += 20
        signals.append(Signal(type="financial_lure", severity="high", description="Financial lure or prize claim detected."))

    threat_hits = _count_matches(text, _THREAT_PATTERNS)
    if threat_hits >= 1:
        score += 20
        signals.append(Signal(type="threat_language", severity="high", description="Threatening language about account suspension or legal action."))

    return min(score, 100), signals


def _count_matches(text: str, patterns: list[str]) -> int:
    return sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
