# PrivacyLens event schema — integration reference for consumers

Everything a downstream consumer (dashboard, reporter, SIEM content) needs to
recognize, parse, and display PrivacyLens data. Current as of PrivacyLens
v0.9.0. Vendor: CybX.

## 1. How to recognize a PrivacyLens event

| Where you read from | Distinguishing marker |
| --- | --- |
| Raw NDJSON log (`logs/findings.json`) | every line is one JSON object starting `{"tool":"PrivacyLens","privacylens_event":"..."` |
| Insights alert (alerts.json / `wazuh-alerts-*` index) | `rule.id` in **100950–100963** and/or `rule.groups` contains `privacylens` (also `pii`, `dlp`); event fields appear under `data.*` (e.g. `data.tool` = `PrivacyLens`) |
| CEF / network syslog | header contains `CEF:0|CybX|PrivacyLens|` ; RFC 3164 program name is `privacylens` |

**Version compatibility:** binaries ≤ 0.7.0 named the event-type key
`event_type` instead of `privacylens_event`. Consumers should read
`privacylens_event`, falling back to `event_type`, until all scanners are
upgraded. (The rename exists because the Insights manager's stock Suricata rule 86600
captures any JSON event carrying `timestamp` + `event_type`.)

## 2. The three event types (JSON / NDJSON)

Values are **masked by default** (`"masked": true`): emails keep first char +
domain (`j***********@example.com`), everything else keeps its last four
alphanumerics and all separators (`***-**-9999`, `**** **** **** 1111`).
Masking covers the whole `context` line: sibling findings on the same line
are masked in each other's context, and in credential-export CSVs (any
`password` column) the password next to a matched username appears as the
fixed string `********` (0.9.2+; earlier binaries leaked neighboring values
in `context`). `masked: false` means the run was executed with `-show-full`
and values are real — treat the whole payload as PII.

### 2.1 `finding` — one per PII hit

```json
{"tool":"PrivacyLens","privacylens_event":"finding","version":"0.8.0","timestamp":"2026-07-13T11:25:48-04:00","host":"MacBook-Pro-2.local","masked":true,"category_id":"credit-card","path":"testdata/card_list.xlsx","file_name":"card_list.xlsx","category":"Credit Card","confidence":"high","line":6,"match":"************1111","context":"************1111"}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | always `PrivacyLens` |
| `privacylens_event` | string | `finding` |
| `version` | string | scanner version |
| `timestamp` | string | RFC 3339. Events stream as files are scanned, so each carries its write time; the `scan_summary`'s timestamp marks the end of the run |
| `host` | string | machine hostname |
| `masked` | bool | whether `match`/`context` are masked |
| `category_id` | string | stable machine slug — key display/filter logic on this |
| `category` | string | human display name |
| `confidence` | string | `high` \| `medium` \| `low` |
| `path` | string | absolute or root-relative file path |
| `file_name` | string | basename of `path` |
| `line` | int | 1-based line number within the extracted text (within the page, when `page` is present) |
| `match` | string | the (masked) PII value |
| `context` | string | the (masked) line it appeared on |
| `ocr` | bool | present and `true` when the text was read via OCR (0.9.0+). OCR misreads characters — weight lower / verify against the source. Absent otherwise |
| `page` | int | 1-based page number, present only for OCR'd multi-page documents (0.9.0+) |

### 2.2 `needs_ocr` — one per document that could NOT be searched

Scan/image-only document with no text layer; contents are unknown — a
coverage gap, not a clean file. Display it as such.

```json
{"tool":"PrivacyLens","privacylens_event":"needs_ocr","version":"0.8.0","timestamp":"...","host":"...","path":"testdata/scanned_intake_form.pdf","file_name":"scanned_intake_form.pdf"}
```

### 2.3 `scan_summary` — exactly one per run (heartbeat + totals)

Lets a dashboard distinguish "scanned clean" from "scan never ran": a host
with findings=0 summaries is healthy; a host with NO recent summary at all
has a broken/missing scan schedule.

```json
{"tool":"PrivacyLens","privacylens_event":"scan_summary","version":"0.9.0","timestamp":"...","host":"...","roots":["testdata"],"duration":"1ms","masked":true,"findings":24,"files_scanned":6,"files_skipped":0,"files_need_ocr":1,"files_ocr":0,"files_errored":0}
```

`roots` (string array), `duration` (Go duration string, e.g. `4.2s`),
`findings`, `files_scanned`, `files_skipped`, `files_need_ocr`,
`files_ocr` (documents read via OCR, 0.9.0+), `files_errored` (ints).

## 3. Categories (`category` ↔ `category_id`)

| category (display) | category_id (stable key) |
| --- | --- |
| SSN | `ssn` |
| ITIN | `itin` |
| Credit Card | `credit-card` |
| Bank Account Number | `bank-account-number` |
| Bank Routing Number | `bank-routing-number` |
| Date of Birth | `date-of-birth` |
| Driver's License | `driver-s-license` |
| Email Address | `email-address` |
| Phone Number | `phone-number` |
| Passport Number | `passport-number` |
| Medicare ID (HIPAA) | `medicare-id-hipaa` |
| Medical Record Number (HIPAA) | `medical-record-number-hipaa` |
| Diagnosis Code (HIPAA) | `diagnosis-code-hipaa` |
| Document Marking (CMMC) | `document-marking-cmmc` |
| Scope Indicator (CMMC) | `scope-indicator-cmmc` |

The two CMMC categories (0.9.2+) flag regulated-document indicators.
Document Marking: CUI / FCI acronyms and banner markings (`CUI//SP-…`), the
spelled-out phrases, and TLP 2.0 markings (`TLP:RED`, `TLP:AMBER[+STRICT]`,
`TLP:GREEN`; `TLP:CLEAR` is shareable and not flagged). Scope Indicator:
content suggesting a document falls under CMMC even without a marking —
ITAR / EAR99, spelled-out export-control regimes, DFARS 252.204-70xx
clauses, NIST SP 800-171 references, DoD distribution statements B–F, and
DoD contract numbers (PIID shape, requires a contract-style label nearby).
Unlike every other category, the `match` value stays unmasked even when
`masked: true` — the marking is an indicator, not a secret (other findings'
values appearing in the same `context` line are still masked as usual).

Slug rule (for future categories): lowercase, every run of non-alphanumerics
becomes one `-`, trailing `-` trimmed.

## 4. Insights rules that fire on these events

| rule.id | level | fires on | groups (beyond privacylens,pii,dlp) |
| --- | --- | --- | --- |
| 100950 | 0 (silent base) | any PrivacyLens JSON event | |
| 100957 | 0 (silent base) | any syslog/CEF-decoded event | |
| 100958 | 0 (silent base) | ≤0.7.0 events rescued from Suricata rule 86600 | |
| 100951 | 10 | `confidence: high` | gdpr_II_5.1.f, hipaa_164.312.b, pci_dss_3.4 |
| 100952 | 7 | `confidence: medium` | gdpr_II_5.1.f |
| 100953 | 12 | `category_id`: ssn, itin, credit-card | pci_dss_3.4, gdpr_II_5.1.f |
| 100954 | 12 | `category_id`: medicare-id-hipaa, medical-record-number-hipaa, diagnosis-code-hipaa | hipaa_164.312.b |
| 100955 | 5 | `privacylens_event` starts with `needs` | |
| 100956 | 3 | `privacylens_event` starts with `scan` | |
| 100959 | 8 | 100951 match with `ocr: true` — OCR-read, verify against source | gdpr_II_5.1.f, hipaa_164.312.b, pci_dss_3.4 |
| 100960 | 10 | 100953 match with `ocr: true` | pci_dss_3.4, gdpr_II_5.1.f |
| 100961 | 10 | 100954 match with `ocr: true` | hipaa_164.312.b |
| 100962 | 10 | `category_id`: document-marking-cmmc, scope-indicator-cmmc | cmmc, nist_800_171 |
| 100963 | 8 | 100962 match with `ocr: true` | cmmc, nist_800_171 |

A single finding can trigger both a confidence rule and a category
escalation; Insights emits the highest-priority match. In an Insights alert, all
event fields from §2 live under `data.` (`data.category_id`,
`data.confidence`, `data.path`, …); the agent identity is in `agent.name` /
`agent.id`; `rule.level`, `rule.id`, `rule.description`, `rule.groups` as
usual.

## 5. CEF / network syslog format (alternate transport)

RFC 3164 header + CEF payload. The `<PRI>` tag is present only on network
delivery (`-syslog-addr`), where the receiver strips it; PRI values:
high=132 (local0.warning), medium=133 (local0.notice), low/other=134
(local0.info). CEF written to a file (`-syslog-out`) has no PRI — lines
start with the timestamp header (`Jul 15 14:28:47 host privacylens: CEF:0|…`)
so an agent tailing the file with `<log_format>syslog</log_format>`
pre-decodes cleanly (a leading `<133>` would defeat the pre-decoder and
nothing would reach the rules).

Prematch anchors (stable, safe to key on):

- finding: `PII detected: ` — signature ID = `category_id` slug, severity 8/5/3 for high/medium/low
  `CEF:0|CybX|PrivacyLens|<version>|ssn|PII detected: SSN|8|filePath=... fname=... cn1Label=lineNumber cn1=14 cs1Label=category cs1=SSN cs2Label=confidence cs2=high cs3Label=match cs3=***-**-9999 msg=<context>`
- needs OCR: `Document not searched - needs OCR` — signature ID `needs-ocr`, severity 5
- summary: `PII scan completed` — signature ID `scan-summary`, severity 3
  (`cn1`=findings, `cn2`=filesScanned, `cn3`=filesNeedOcr, `msg`=roots/duration/skipped/unreadable)

CEF escaping: `\` `=` and newlines escaped in extension values; `\` `|` in
header fields.

## 6. Where the raw data lives

- NDJSON log the Insights agent tails: `C:\ProgramData\PrivacyLens\logs\
  findings.json` (Windows) / `/var/log/privacylens/findings.json` (else).
  As of 0.9.2, **every** scan — flagless, `-json`/`-csv`/`-html`, manifest,
  or GUI — appends here whenever the directory exists (the installer
  creates it and grants Users write access), regardless of other output
  flags. Only `-syslog-out`, `-syslog-addr`, or `-no-findings-log` override
  it; if the machine-wide log is unwritable the scan warns loudly and
  falls back to the per-user log (`<DataDir>/logs/findings.json`). Earlier
  binaries silently skipped event streaming whenever `-json`/`-csv`/`-html`
  was used. Lines are streamed while the scan runs (finding events as each
  file completes, `needs_ocr` + `scan_summary` at the end), so consumers
  see data flowing throughout a long scan.
- Nested archive report `reports/scan-<timestamp>.json`: same finding fields
  inside a `findings[]` array plus a `stats` object — for humans/archive.
  Do NOT ingest it as an event stream.

## 7. Presenting findings: group by document

Every transport above deliberately carries **one record per finding** — a
SIEM alerts on individual hits. Human-facing views (as of 0.9.2, the
PrivacyLens GUI and HTML report both do this) should instead show **one
entry per document listing all PII found in it**:

- **Group key:** `path` (report JSON / NDJSON) or `data.path` (Insights
  alerts). Alerts from multiple machines must also group by the agent
  (`agent.name`/`agent.id`) — the same `C:\Users\...` path exists on every
  host.
- **Ordering guarantee:** the archive report's `findings[]` is sorted by
  path then line, so grouping is a single pass over consecutive records.
  The NDJSON stream is grouped per file but files complete in scan order,
  not sorted order.
- **Per-document summary:** count findings per `category` (display) or
  `category_id` (stable key) — e.g. "SSN ×2 · Email Address ×5" — and show
  the individual matches (category, confidence, line, match, context)
  beneath.
- Only `privacylens_event: "finding"` records are findings; `needs_ocr`
  and `scan_summary` events must not enter the grouping.
