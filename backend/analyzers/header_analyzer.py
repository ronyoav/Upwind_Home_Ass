import re
from backend.models.email_request import EmailHeaders, Signal

# Known legitimate third-party email senders (ATS, marketing platforms)
_TRUSTED_THIRD_PARTY_DOMAINS = {
    # ATS / HR platforms
    "comeet-notifications.com", "comeet.co",
    "sparkhire.com", "spark-hire.com",
    "greenhouse.io", "greenhouse-mail.io",
    "lever.co", "levermail.com",
    "jobvite.com",
    "workable.com", "workablemail.com",
    "bamboohr.com",
    "smartrecruiters.com",
    "myworkday.com", "workday.com",
    "icims.com",
    "taleo.net",
    "successfactors.com", "successfactors.eu",
    "sap.com",
    "oracle.com",
    # Email marketing & transactional
    "sendgrid.net", "sendgrid.com",
    "mailchimp.com", "mandrillapp.com",
    "hubspotemail.net", "hubspot.com",
    "brevo.com", "sendinblue.com",
    "activecampaign.com",
    "mailgun.org", "mailgun.net",
    "amazonses.com",
    "sparkpostmail.com",
    "postmarkapp.com",
    "customer.io",
    "klaviyo.com",
    "constantcontact.com",
    "campaignmonitor.com",
    # Calendar & notifications
    "calendar-server.bounces.google.com",
    "notifications.google.com",
    "zoom.us",
    "calendly.com",
    # E-commerce & payments
    "shopify.com", "mail.shopify.com",
    "stripe.com",
    "paypal.com",
    # LinkedIn & social
    "linkedin.com", "e.linkedin.com",
    # Cloud providers
    "notifications.aws.amazon.com",
    "azure.com",
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

    # Display name spoofing: "PayPal <attacker@gmail.com>"
    if headers.from_address:
        display_name = _extract_display_name(headers.from_address)
        actual_domain = _extract_domain(headers.from_address)
        if display_name and actual_domain:
            spoofed_brand = _spoofed_brand(display_name, actual_domain)
            if spoofed_brand:
                score += 35
                signals.append(Signal(
                    type="display_name_spoofing",
                    severity="high",
                    description=f"Display name claims to be '{spoofed_brand}' but email is sent from '{actual_domain}'.",
                ))

    # Lookalike / homoglyph domain check
    if headers.from_address:
        domain = _extract_domain(headers.from_address)
        if domain and _is_lookalike(domain):
            score += 30
            signals.append(Signal(
                type="lookalike_domain",
                severity="high",
                description=f"Sender domain '{domain}' resembles a well-known brand (possible homoglyph or typosquat).",
            ))

    return min(score, 100), signals


def _extract_domain(address: str) -> str | None:
    match = re.search(r"@([\w\.\-]+)", address)
    return match.group(1).lower() if match else None


def _extract_display_name(address: str) -> str | None:
    """Extract the human-readable name from 'Name <email@domain.com>'."""
    match = re.match(r'^"?([^"<]+)"?\s*<', address.strip())
    return match.group(1).strip().lower() if match else None


# Known brands: display-name keyword → legitimate sending domain
_KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bank of america": "bankofamerica.com",
    "linkedin": "linkedin.com",
}


def _spoofed_brand(display_name: str, actual_domain: str) -> str | None:
    """Return brand name if display name claims a known brand but domain doesn't match."""
    for brand, legit_domain in _KNOWN_BRANDS.items():
        if brand in display_name and not actual_domain.endswith(legit_domain):
            return brand
    return None


def _is_lookalike(domain: str) -> bool:
    # Skip exact legitimate domains immediately
    if domain in _KNOWN_BRANDS.values():
        return False

    # Normalize unicode homoglyphs (Cyrillic/Greek → ASCII lookalikes)
    normalized = (
        domain
        .replace("а", "a").replace("е", "e").replace("о", "o")   # Cyrillic
        .replace("р", "p").replace("с", "c").replace("х", "x")
        .replace("ο", "o").replace("ν", "v")                      # Greek
    )
    # Normalize multi-character visual substitutions: rn→m, vv→w, cl→d, li→li(1→l)
    visual = (
        normalized
        .replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .replace("1", "l")
        .replace("0", "o")
    )
    for brand, legit in _KNOWN_BRANDS.items():
        brand_word = brand.split()[0]
        for candidate in (normalized, visual):
            if brand_word in candidate and domain != legit:
                return True
    # Digit-substitution typosquats — only fire if NOT a legit domain
    for candidate in (normalized, visual):
        if re.search(r"(pay[p\d]a[l1]|g[o0]{2}gle|micr[o0]s[o0]ft|app[l1]e|amaz[o0]n)", candidate):
            if domain not in _KNOWN_BRANDS.values():
                return True
    return False
