# Gmail Malicious Email Scorer

A Gmail Add-on that analyzes incoming emails in real-time and assigns a phishing risk score using a hybrid rule engine + LLM architecture.

---

## Architecture & Flow

```
┌─────────────────────────────────────────────────────┐
│          Phase 1 — Gmail Add-on                     │
│  • Client-side PII stripping (SSN, credit cards)    │
│  • Tracking pixel removal                           │
│  • URL extraction + PII redaction                   │
│  • SHA-256 hash of attachments (≤5MB, not the file) │
└────────────────────┬────────────────────────────────┘
                     │ POST /api/v1/analyze
                     │ { subject, headers, body_html,
                     │   urls, attachments[{name,mime,sha256}] }
                     ▼
       ┌─────────────────────────────────────────┐
       │  Phase 2 — Backend (parallel)           │
       ├──────────────────────┬──────────────────┤
       │                      │                  │
       ▼                      ▼                  │
┌──────────────────┐  ┌────────────────┐          │
│ Sanitizer        │  │  VirusTotal    │          │
│ HTML clean       │  │  sha256 →      │          │
│ PII strip        │  │  VT API →      │          │
│  (2nd layer)     │  │  70+ AV engines│          │
│ Prompt injection │  └───────┬────────┘          │
│  removal → LLM   │          │                   │
│ Link mismatch    │          │                   │
│ Base64 detect    │          │                   │
└────────┬─────────┘          │                   │
      │                      │                   │
      └──────────┬───────────┘                   │
                 │ Phase 3 waits for sanitizer + VT
                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Phase 3 — Rule Engine + LLM (parallel)                     │
  │                                                             │
  │  ┌────────────┐  ┌──────────────┐  ┌───────────────┐       │
  │  │  Headers   │  │   Content    │  │     URLs      │       │
  │  │ SPF/DKIM   │  │ Urgency lang │  │ Unshorten→    │       │
  │  │ DMARC      │  │ Credentials  │  │  analyze real │       │
  │  │ Spoofing   │  │ Financial    │  │ Bad domain    │       │
  │  │ Lookalike  │  │ Ransomware   │  │ text≠href     │       │
  │  └────────────┘  │ QR/CAPTCHA   │  │ Base64 score  │       │
  │                  │ Sextortion   │  └───────────────┘       │
  │  ┌────────────┐  └──────────────┘                          │
  │  │Attachments │                                            │
  │  │ exe/iso    │  ┌──────────────────────────────────────┐  │
  │  │ PDF/Office │  │  LLM (Haiku) — feature extractor     │  │
  │  │ double ext │  │                                      │  │
  │  │ MIME mis-  │  │  Returns structured JSON:            │  │
  │  │ match      │  │  • intent: credential_harvesting /   │  │
  │  └────────────┘  │            financial_fraud /         │  │
  │                  │            malware_delivery / spam   │  │
  │                  │  • impersonation: true/false         │  │
  │                  │  • urgency_level: 0–3                │  │
  │                  │  • suspicious_elements: [...]        │  │
  │                  │                                      │  │
  │                  │  Rule Engine scores the JSON →       │  │
  │                  │  LLM cannot set score directly       │  │
  │                  └──────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────┘
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

## What We Check — Quick Reference

| # | Signal | What we observe | What it means |
|---|--------|-----------------|---------------|
| 1 | `spf_fail` | SPF=fail in header | Sending server is not authorized to send from this domain |
| 2 | `dkim_fail` | DKIM=fail | Email was modified after sending, or signature is forged |
| 3 | `dmarc_fail` | DMARC=fail | Domain policy explicitly rejects this message |
| 4 | `reply_to_mismatch` | From: bank.com / Reply-To: evil.com | Replies go to a different party than the apparent sender |
| 5 | `display_name_spoofing` | "PayPal" \<attacker@gmail.com\> | Display name impersonates a brand; actual address is unrelated |
| 6 | `lookalike_domain` | arnazon.com, paypa1.com, miсrosoft.com | Typosquat or homoglyph of a known brand |
| 7 | `link_text_mismatch` | Shows "google.com" → href points to evil.ru | User sees one link, clicks another |
| 8 | `url_shortener` | bit.ly, tinyurl | Destination resolved via HEAD request; real URL analyzed for all other signals |
| 9 | `suspicious_tld` | .xyz, .top, .click, .tk | TLDs commonly used in phishing infrastructure |
| 10 | `ip_url` | http://185.23.4.1/login | No legitimate domain — hides who owns the server |
| 11 | `base64_payload` | Long base64 string in HTML body | Hides malicious URLs or content from spam filters — rendered only when the user clicks |
| 12 | `credential_phishing` | "confirm your details", "verify your account" | Email requests login credentials or personal verification |
| 13 | `urgency_language` | "act now", "expires in 24h" | Pressure designed to bypass critical thinking |
| 14 | `financial_lure` | gift card, bitcoin, lottery | Financial bait to manipulate the recipient |
| 15 | `ransomware` | "your files are encrypted", "pay to recover" | Ransom demand — files held hostage |
| 16 | `sextortion` | "I recorded you", "pay or I'll share" | Extortion using fabricated or stolen compromising material |
| 17 | `double_extension` | invoice.pdf.exe | Looks like a document, executes as code |
| 18 | `mime_mismatch` | Extension .pdf, MIME: application/javascript | File is not what its extension claims |
| 19 | `dangerous_attachment` | .exe, .ps1, .iso, .hta | File type that directly executes code |
| 20 | `virustotal_malicious` | SHA-256 known to VirusTotal | 3+ AV engines have flagged this exact file |

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
| **URLs** | `url_shortener` — bit.ly, tinyurl; real destination resolved via HEAD request and analyzed | Medium | +15 |
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
| | `double_extension` — invoice.pdf.exe (looks like doc, runs as code) | High | +40 |
| | `mime_mismatch` — extension says .pdf, MIME type says application/javascript | High | +35 |
| | `virustotal_malicious` — SHA-256 flagged malicious by 3+ AV engines | High | +50 |
| | `virustotal_suspicious` — SHA-256 flagged suspicious by 1+ AV engines | Medium | +25 |
| **AI Analysis** | `llm_intent` — credential harvesting / financial fraud / malware delivery | High | +35–40 |
| | `llm_intent` — spam | Low | +10 |
| | `llm_impersonation` — brand or identity impersonation detected | High | +25 |
| | `llm_urgency` — extreme urgency (level 3) or moderate (level 2) | Medium/High | +8/+15 |
| | `llm_suspicious_elements` — AI observations, up to 3 items shown | Medium | — |

---

## Trade-offs

### VirusTotal Hash Lookup vs. Sandbox Execution

Sandbox execution runs the actual file inside a virtual machine and observes its behavior — the gold standard for malware detection. It was considered and rejected for three reasons:

- **Latency** — sandbox analysis takes 2–5 minutes per file. A Gmail Add-on must return a result in seconds to be usable.
- **Resources** — each file requires a dedicated VM with CPU and RAM allocation. For a demo-scale add-on this is significant over-engineering.
- **Privacy** — attachments may contain sensitive user data (employment contracts, medical documents). Uploading file contents to an external execution environment raises legitimate privacy concerns the user never consented to. Sending only a SHA-256 hash means the backend never sees the file contents.

The trade-off accepted: zero-day malware with no prior VirusTotal history will not be caught. Known malware is caught immediately.

---

### Celery Worker Queue vs. Render Instance Scaling

The scalable architecture would use Redis as a message broker with Celery workers consuming tasks from the queue — decoupling request intake from processing and handling large load spikes gracefully.

This was rejected because running a Celery worker is a separate paid service on Render. Instead, the `render.yaml` is configured with up to 5 parallel instances of the FastAPI service itself, which provides horizontal scaling sufficient for the demo scope without the added infrastructure cost and complexity.

The trade-off accepted: under extreme load the system will queue at the HTTP layer rather than at a dedicated task queue, which is less efficient but operationally simpler and free.

---

## If I Had More Time

### Celery Worker Queue for True Horizontal Scaling

The current setup scales by running up to 5 parallel FastAPI instances via `render.yaml`. A proper production architecture would introduce Celery with Redis as a message broker — decoupling HTTP request intake from analysis processing. This would allow workers to scale independently from the API layer and handle sustained high-volume traffic more gracefully than HTTP-layer queuing.

### Feedback Loop — "Report as Mistake" Button

A "Report False Positive" button in the Gmail Add-on UI would collect real-world mislabeled emails from users. This data would be used to tune Rule Engine thresholds and scores based on actual field evidence — the system improves the more it is used, which is product thinking beyond pure engineering.

If the project were to migrate to a model that supports fine-tuning (e.g., a locally hosted open-source model via Ollama), the collected false positive dataset could be used to fine-tune the model directly. This would also eliminate per-call API costs and remove privacy concerns entirely, since inference would run locally with no data leaving the server.

### Sandbox Execution for Zero-Day Attachment Detection

The current approach catches known malware via VirusTotal hash lookup but misses zero-day threats with no prior detection history. A sandbox would execute the attachment inside an isolated VM and observe its runtime behavior — catching novel malware regardless of whether it appears in any threat-intel database. The latency and resource cost make this impractical for a demo add-on but it is the right long-term direction for attachment analysis.

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


### Why Redis cache?

LLM calls are the only expensive operation (~500ms, ~$0.001 each). Identical emails (mass phishing campaigns) are analyzed once and served from cache for 1 hour. If Redis is unavailable, the system falls back gracefully — no crash, just no cache.

### Why does VirusTotal run in parallel with the sanitizer?

VirusTotal only needs the SHA-256 hash that the Add-on already computed client-side — it is completely independent of the sanitizer output. Both run in parallel (Phase 1), and their results are combined before the rule engine runs (Phase 2). This cuts total latency by the duration of whichever is slower.

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
