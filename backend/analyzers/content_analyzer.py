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

_RANSOMWARE_PATTERNS = [
    r"\byour files (have been|are) encrypted\b",
    r"\bencrypted (all )?your (files|data|documents)\b",
    r"\bpay (to )?recover\b",
    r"\bdecryption key\b",
    r"\bransom\b",
    r"\byour (data|files|computer) (has been|have been) (locked|held hostage)\b",
    r"\bpay within \d+ hours?\b",
    r"\bbitcoin (wallet|address|payment)\b",
]

_QR_PATTERNS = [
    r"\bscan (this |the )?(qr|q\.r\.?) ?code\b",
    r"\bpoint your (camera|phone) (at|to)\b",
    r"\bqr code (below|above|attached)\b",
    r"\bscan to (verify|login|sign in|confirm|access|pay)\b",
    r"\buse your (camera|phone) to scan\b",
]

_SEXTORTION_PATTERNS = [
    r"\bI have (access to|hacked|infected) your (camera|webcam|device|computer)\b",
    r"\bI (recorded|filmed|captured) you\b",
    r"\bwhile you (were )?visiting\b",
    r"\byour (contacts|friends|family) will (receive|see)\b",
    r"\bsend .{0,30}(bitcoin|btc|crypto).{0,30}or\b",
    r"\bembarrassing (video|footage|recording)\b",
    r"\bdo not (reply|contact|tell)\b.{0,50}(police|anyone)\b",
    r"\bI will (send|share|release) (the )?(video|footage|recording|photos?)\b",
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

    qr_hits = _count_matches(text, _QR_PATTERNS)
    if qr_hits >= 1:
        score += 20
        signals.append(Signal(type="qr_code_lure", severity="medium", description="Email requests QR code scan — destination URL is hidden and cannot be verified."))

    ransomware_hits = _count_matches(text, _RANSOMWARE_PATTERNS)
    if ransomware_hits >= 1:
        score += 40
        signals.append(Signal(type="ransomware", severity="high", description="Ransomware language detected — claims files are encrypted or demands payment for recovery."))

    sextortion_hits = _count_matches(text, _SEXTORTION_PATTERNS)
    if sextortion_hits >= 1:
        score += 40
        signals.append(Signal(type="sextortion", severity="high", description="Sextortion attempt detected — claims to have compromising material and demands payment."))

    return min(score, 100), signals


def _count_matches(text: str, patterns: list[str]) -> int:
    return sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
