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
└──────┬──────────────────────────────────────────────┘
       │
       ├─────────────────────────────────────────────┐
       │              Rule Engine (70%)              │
       │                                             │
       │  ┌─────────────┐  ┌─────────────────────┐  │
       │  │   Headers   │  │      Content        │  │
       │  │  SPF/DKIM   │  │  Urgency · Creds    │  │
       │  │  DMARC      │  │  Financial · Threats│  │
       │  │  Spoofing   │  │  Ransomware · QR    │  │
       │  │  Lookalike  │  │  Sextortion         │  │
       │  └─────────────┘  └─────────────────────┘  │
       │  ┌─────────────┐  ┌─────────────────────┐  │
       │  │    URLs     │  │    Attachments      │  │
       │  │  Shorteners │  │  High-risk (exe/iso)│  │
       │  │  Bad domains│  │  Medium (PDF/Office)│  │
       │  │  text≠href  │  └─────────────────────┘  │
       │  │  IP URLs    │                            │
       │  └─────────────┘                            │
       └─────────────────────────────────────────────┘
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
| | `dkim_fail` — DKIM signature invalid | High | +20 |
| | `dmarc_fail` — DMARC policy failed | High | +20 |
| | `display_name_spoofing` — "PayPal" but sent from gmail.com | High | +35 |
| | `reply_to_mismatch` — Reply-To differs from From domain | High | +20 |
| | `lookalike_domain` — arnazon.com, miсrosoft.com (homoglyph) | High | +30 |
| **Content** | `urgency_language` — "act now", "expires in 24h" | Medium/High | +10/+20 |
| | `credential_phishing` — "verify your account/password" | High | +25 |
| | `financial_lure` — gift cards, bitcoin, lottery, inheritance | High | +20 |
| | `threat_language` — "legal action", "account will be deleted" | High | +20 |
| | `ransomware` — "files encrypted", "pay to recover" | High | +40 |
| | `sextortion` — "I recorded you", "pay or I'll share" | High | +40 |
| | `qr_code_lure` — "scan this QR code" (hides destination) | Medium | +20 |
| **URLs** | `url_shortener` — bit.ly, tinyurl (destination hidden) | Medium | +15 |
| | `suspicious_tld` — .xyz, .top, .click, .loan | High | +20 |
| | `ip_url` — http://185.x.x.x (no domain) | High | +25 |
| | `http_url` — unencrypted links | Low | +10 |
| | `known_bad_domain` — matches threat-intel feed | High | +40 |
| | `link_text_mismatch` — displays "paypal.com" → links to evil.xyz | High | +30 |
| **Attachments** | `dangerous_attachment` — .exe, .js, .iso, .ps1 | High | +40 |
| | `suspicious_attachment` — .pdf, .docm, .xlsm (macro risk) | Medium | +15 |
| **AI Analysis** | `llm_intent` — credential harvesting / financial fraud / malware | High | +35–40 |
| | `llm_impersonation` — brand or identity impersonation | High | +25 |
| | `llm_urgency` — extreme or moderate urgency pressure | Medium/High | +8/+15 |
| | `llm_suspicious_elements` — AI observations (up to 4) | Medium | — |

---

## Design Decisions

### Why hybrid rule engine + LLM?

Rule engines are deterministic and explainable — every signal maps to a concrete observation with a fixed score. LLMs understand context and nuance that rules miss (e.g., tone, intent, novel phishing narratives). The 70/30 split keeps the system explainable by default while benefiting from AI analysis.

### Why can't the LLM inflate the score?

The LLM never returns a score directly. It returns structured features (intent, urgency level, impersonation flag) which are then scored by a deterministic rule engine. A prompt-injected email that tricks the LLM into saying `"score": 100` has no effect.

### Why Redis cache?

LLM calls are the only expensive operation (~500ms, ~$0.001 each). Identical emails (mass phishing campaigns) are analyzed once and served from cache for 1 hour. If Redis is unavailable, the system falls back gracefully — no crash, just no cache.

### Why client-side PII stripping?

PII (SSN, credit cards, phone numbers) is stripped in the Gmail Add-on before the payload leaves the browser. The backend never sees raw personal data. This is privacy by design — the backend receives only what it needs to detect phishing.

### Why not open attachments?

Opening attachments would require executing untrusted code in a sandbox — a separate security product in itself (e.g., Proofpoint, Mimecast). We analyze attachment metadata (filename, MIME type) and the surrounding email context instead. This also avoids privacy concerns around reading users' documents.

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
| AI Analysis | Claude Haiku (Anthropic) |
| Cache | Redis (Render Key Value) |
| HTML parsing | BeautifulSoup4 + lxml |
| Schema validation | Pydantic v2 |
| Gmail Add-on | Google Apps Script |
| Deployment | Render (auto-deploy on push to main) |
