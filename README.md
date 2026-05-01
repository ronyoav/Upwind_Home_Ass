# Gmail Malicious Email Scorer

A Gmail Add-on that analyzes incoming emails in real-time and assigns a phishing risk score using a hybrid rule engine + LLM architecture.

---

## Architecture & Flow

```
┌─────────────────────────────────────────────────────┐
│                  Gmail Add-on                       │
│  • Client-side PII stripping (SSN, credit cards)    │
│  • Tracking pixel removal                           │
│  • URL extraction + PII redaction                   │
└────────────────────┬────────────────────────────────┘
                     │ POST /api/v1/analyze
                     ▼
┌─────────────────────────────────────────────────────┐
│              Sanitizer Pipeline                     │
│  HTML cleaner → PII stripper →                      │
│  Prompt injection filter → Content minimizer        │
│  Link mismatch extractor · Base64 payload detector  │
└──────┬──────────────────────────────────────────────┘
       │
       ├─────────────────────────────────────────────────┐
       │              Rule Engine (70%)                  │
       │                                                 │
       │  ┌──────────────────┐  ┌─────────────────────┐  │
       │  │     Headers      │  │      Content        │  │
       │  │  SPF/DKIM/DMARC  │  │  Urgency · Creds    │  │
       │  │  Reply-To spoof  │  │  Financial · Threats│  │
       │  │  Display name    │  │  Ransomware · QR    │  │
       │  │  Lookalike domain│  │  CAPTCHA · Sextortion│  │
       │  │  (homoglyph/typo)│  └─────────────────────┘  │
       │  └──────────────────┘                           │
       │  ┌──────────────────┐  ┌─────────────────────┐  │
       │  │      URLs        │  │    Attachments      │  │
       │  │  Shorteners      │  │  High-risk (exe/iso)│  │
       │  │  Bad domains     │  │  Medium (PDF/Office)│  │
       │  │  text≠href       │  │  VirusTotal hash    │  │
       │  │  IP URLs         │  │  lookup (SHA-256)   │  │
       │  │  Phishing keywords│ └─────────────────────┘  │
       │  │  Redirect params │                           │
       │  │  Base64 payload  │                           │
       │  └──────────────────┘                           │
       └─────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│           LLM Analyzer — Claude Haiku (30%)         │
│                                                     │
│  Redis Cache (TTL 1h)                               │
│    hit  → return cached result                      │
│    miss → call API → validate schema → cache        │
│                                                     │
│  Extracts: intent · impersonation · urgency · tone  │
│  Schema validation: Pydantic (LLM cannot inflate    │
│  score directly — rule engine scores the features)  │
│                                                     │
│  Prompt injection hardened: system prompt explicitly│
│  instructs model to treat email content as data,    │
│  not instructions                                   │
└─────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│                Score Aggregator                     │
│       final = rule_score×0.7 + llm_score×0.3        │
│                                                     │
│   0–30  → ✅ Safe                                   │
│  31–60  → ⚠️  Suspicious                            │
│  61–100 → 🚨 Likely Phishing                        │
└─────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│              Gmail Add-on Card                      │
│  Progress bar · Grouped signals · AI explanation    │
└─────────────────────────────────────────────────────┘
```

---

## Signal Types

| Category | Signal | Severity | Score |
|---|---|---|---|
| **Headers** | `spf_fail` — SPF check failed | High | +25 |
| | `spf_missing` — no SPF record (penalized only for untrusted senders) | Medium | +10 |
| | `dkim_fail` — DKIM signature invalid | High | +20 |
| | `dkim_missing` — no DKIM (penalized only for untrusted senders) | Low | +8 |
| | `dmarc_fail` — DMARC policy failed | High | +20 |
| | `reply_to_mismatch` — Reply-To domain differs from From domain | High | +20 |
| | `display_name_spoofing` — "PayPal" \<attacker@gmail.com\> | High | +35 |
| | `lookalike_domain` — arnazon.com, miсrosoft.com, paypa1.com | High | +30 |
| **Content** | `urgency_language` — "act now", "expires in 24h" | Medium/High | +10/+20 |
| | `credential_phishing` — "verify your account", "confirm your details" | High | +25 |
| | `financial_lure` — gift cards, bitcoin, lottery, inheritance | High | +20 |
| | `threat_language` — "legal action", "account will be deleted" | High | +20 |
| | `qr_code_lure` — "scan this QR code" (hides destination URL) | Medium | +20 |
| | `captcha_lure` — CAPTCHA in email body (hides phishing page from scanners) | Medium | +20 |
| | `ransomware` — "files encrypted", "pay to recover", "decryption key" | High | +40 |
| | `sextortion` — "I recorded you", "pay or I'll share" | High | +40 |
| **URLs** | `url_shortener` — bit.ly, tinyurl (destination hidden) | Medium | +15 |
| | `suspicious_tld` — .xyz, .top, .click, .loan, .tk, .ml, .gq | High | +20 |
| | `ip_url` — http://185.x.x.x (no legitimate domain) | High | +25 |
| | `http_url` — unencrypted links | Low | +10 |
| | `known_bad_domain` — matches threat-intel feed | High | +40 |
| | `phishing_keyword_domain` — domain contains login, verify, secure, account... | Medium | +20 |
| | `long_url` — URL over 100 chars (possible obfuscation) | Low | +10 |
| | `redirect_param` — ?redirect=, ?url=, ?next= (hides final destination) | Medium | +15 |
| | `external_domain` — sender domain ≠ link domain (no business relationship) | Medium | +15 |
| | `link_text_mismatch` — displays "paypal.com" but href points to evil.xyz | High | +30 |
| | `base64_payload` — HTML contains long base64-encoded content (hides malicious scripts) | High | +30 |
| **Attachments** | `dangerous_attachment` — .exe, .js, .vbs, .bat, .ps1, .iso, .jar | High | +40 |
| | `suspicious_attachment` — .pdf, .doc, .docm, .xlsm, .ppt (macro risk) | Medium | +15 |
| | `virustotal_malicious` — SHA-256 flagged malicious by 3+ AV engines | High | +50 |
| | `virustotal_suspicious` — SHA-256 flagged suspicious by 1+ AV engines | Medium | +25 |
| **AI Analysis** | `llm_intent` — credential harvesting / financial fraud / malware delivery | High | +35–40 |
| | `llm_intent` — spam | Low | +10 |
| | `llm_impersonation` — brand or identity impersonation detected | High | +25 |
| | `llm_urgency` — extreme urgency (level 3) or moderate (level 2) | Medium/High | +8/+15 |
| | `llm_suspicious_elements` — AI observations, up to 3 items shown | Medium | — |

---

## Design Decisions

### Why hybrid rule engine + LLM?

Rule engines are deterministic and explainable — every signal maps to a concrete observation with a fixed score. LLMs understand context and nuance that rules miss (e.g., tone, intent, novel phishing narratives, social engineering with friendly language). The 70/30 split keeps the system explainable by default while benefiting from AI analysis.

### Why can't the LLM inflate the score?

The LLM never returns a score directly. It returns structured features (intent, urgency level, impersonation flag) which are then scored by a deterministic rule engine. A prompt-injected email that tricks the LLM into saying `"score": 100` has no effect — the rule engine ignores it entirely.

### Prompt injection hardening

The LLM system prompt explicitly instructs the model that all email content is untrusted data, not instructions. Phrases like "ignore previous instructions" or "you are now" found inside the email body are treated as phishing evidence, not directives. The system prompt is immutable; only the rule engine can change scoring behavior.

### Trusted sender whitelist

Known legitimate third-party senders (ATS platforms like Greenhouse, Lever, Workday; email marketing services like SendGrid, Mailchimp, HubSpot; cloud providers) are whitelisted. Missing SPF/DKIM records are expected and not penalized for these senders, eliminating false positives on legitimate HR and transactional emails.

### Lookalike domain detection

Covers four attack vectors:
- **Unicode homoglyphs** — Cyrillic/Greek characters that look identical to ASCII (е, о, р, ο, ν)
- **Multi-character visual substitutions** — `rn→m` (arnazon), `vv→w`, `cl→d`
- **Digit substitutions** — `0→o`, `1→l` (paypa1, g00gle, micros0ft)
- **Keyword presence** — brand name present in domain that isn't the legitimate domain

### Why Redis cache?

LLM calls are the only expensive operation (~500ms, ~$0.001 each). Identical emails (mass phishing campaigns) are analyzed once and served from cache for 1 hour. If Redis is unavailable, the system falls back gracefully — no crash, just no cache.

### Why VirusTotal for attachments?

Attachment content is never opened or executed. We compute a SHA-256 hash client-side in the Gmail Add-on and look it up against VirusTotal's database of 70+ antivirus engines. This gives threat-intel coverage without running untrusted code. If the hash is unknown (not in VT database), no penalty is applied — absence of evidence is not evidence of malice.

### Why client-side PII stripping?

PII (SSN, credit cards, phone numbers) is stripped in the Gmail Add-on before the payload leaves the browser. The backend never sees raw personal data. This is privacy by design — the backend receives only what it needs to detect phishing.

### Verdict thresholds

| Score | Verdict | Rationale |
|---|---|---|
| 0–30 | Safe | High confidence — few or no signals |
| 31–60 | Suspicious | Enough signals to warn, not enough to condemn |
| 61–100 | Likely Phishing | Multiple high-severity signals converge |

---

## Stack

| Component | Technology |
|---|---|
| Backend | Python · FastAPI |
| AI Analysis | Claude Haiku 4.5 (Anthropic) |
| Threat Intel | VirusTotal API v3 |
| Cache | Redis (Render Key Value) |
| HTML parsing | BeautifulSoup4 + lxml |
| Schema validation | Pydantic v2 |
| Gmail Add-on | Google Apps Script |
| Deployment | Render (auto-deploy on push to main) |
