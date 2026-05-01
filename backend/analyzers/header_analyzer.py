import re
from backend.models.email_request import EmailHeaders, Signal

# Known legitimate third-party email senders (ATS, marketing platforms)
_TRUSTED_THIRD_PARTY_DOMAINS = {
    # ATS platforms
    "comeet-notifications.com", "comeet.co",
    "sparkhire.com", "spark-hire.com",
    "greenhouse.io", "greenhouse-mail.io",
    "lever.co", "levermail.com",
    "jobvite.com",
    "workable.com", "workablemail.com",
    "bamboohr.com",
    "smartrecruiters.com",
    # Email marketing & transactional
    "sendgrid.net", "sendgrid.com",
    "mailchimp.com", "mandrillapp.com",
    "hubspotemail.net", "hubspot.com",
    "brevo.com", "sendinblue.com",
    "activecampaign.com",
    "mailgun.org", "mailgun.net",
    "amazonses.com",
    "sparkpostmail.com",
}


def _is_trusted_sender(headers: EmailHeaders) -> bool:
    """Returns True if the email is sent via a known legitimate third-party service."""
    for field in [headers.from_address, headers.received_from]:
        if not field:
            continue
        domain = _extract_domain(field) or field.lower()
        for trusted in _TRUSTED_THIRD_PARTY_DOMAINS:
            if domain.endswith(trusted):
                return True
    return False


def analyze_headers(headers: EmailHeaders) -> tuple[int, list[Signal]]:
    score = 0
    signals = []

    trusted = _is_trusted_sender(headers)

    # SPF check
    if headers.spf and "fail" in headers.spf.lower():
        score += 25
        signals.append(Signal(type="spf_fail", severity="high", description="SPF check failed — sender domain not authorized."))
    elif not headers.spf or headers.spf.lower() in ("none", "neutral"):
        if not trusted:
            score += 10
            signals.append(Signal(type="spf_missing", severity="medium", description="No SPF record found for sender domain."))
        else:
            signals.append(Signal(type="spf_missing", severity="low", description="No SPF record — sent via trusted third-party service (expected)."))

    # DKIM check
    if headers.dkim and "fail" in headers.dkim.lower():
        score += 20
        signals.append(Signal(type="dkim_fail", severity="high", description="DKIM signature invalid — email may have been tampered with."))
    elif not headers.dkim or headers.dkim.lower() in ("none", "neutral"):
        if not trusted:
            score += 8
            signals.append(Signal(type="dkim_missing", severity="low", description="No DKIM signature found."))
        else:
            signals.append(Signal(type="dkim_missing", severity="low", description="No DKIM on original domain — signed by trusted third-party service (expected)."))

    # DMARC check
    if headers.dmarc and "fail" in headers.dmarc.lower():
        score += 20
        signals.append(Signal(type="dmarc_fail", severity="high", description="DMARC policy failed — domain alignment check failed."))

    # Reply-To mismatch
    if headers.from_address and headers.reply_to:
        from_domain = _extract_domain(headers.from_address)
        reply_domain = _extract_domain(headers.reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            score += 20
            signals.append(Signal(
                type="reply_to_mismatch",
                severity="high",
                description=f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}).",
            ))

    # Lookalike domain check
    if headers.from_address:
        domain = _extract_domain(headers.from_address)
        if domain and _is_lookalike(domain):
            score += 30
            signals.append(Signal(
                type="lookalike_domain",
                severity="high",
                description=f"Sender domain '{domain}' resembles a well-known brand but is not legitimate.",
            ))

    return min(score, 100), signals


def _extract_domain(address: str) -> str | None:
    match = re.search(r"@([\w\.\-]+)", address)
    return match.group(1).lower() if match else None


# Known brands and their legitimate domains
_KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "bank": None,
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
}


def _is_lookalike(domain: str) -> bool:
    domain_lower = domain.lower()
    for brand, legit in _KNOWN_BRANDS.items():
        if brand in domain_lower and domain_lower != legit:
            return True
    # Homoglyph / typosquat heuristic: digits substituting letters
    if re.search(r"(pay[p\d]a[l1]|g[o0]{2}gle|micr[o0]s[o0]ft|app[l1]e)", domain_lower):
        return True
    return False
