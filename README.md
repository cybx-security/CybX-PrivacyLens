# PrivacyLens

Cross-platform PII discovery scanner. Point it at folders and it finds
personally identifiable information — Social Security numbers, credit cards,
driver's licenses, medical identifiers (HIPAA), bank details, and more — then
reports **which file**, **which line**, **what category**, and the
**surrounding context** of every hit, so the data can be moved or encrypted.

Runs on Windows, Linux, and macOS as a single self-contained binary with no
runtime dependencies.

## Quick start

```sh
# Scan a folder, get a summary in the terminal
privacylens ~/Documents

# Produce customer-facing reports
privacylens -html report.html -json report.json -csv report.csv /shared/finance

# Only high-confidence findings, skipping backup dirs
privacylens -min-confidence high -exclude node_modules -exclude '*.bak' /data

# Ship findings to a SIEM (see "Insights / SIEM integration" below)
privacylens -syslog-addr udp://insights.example.com:514 /data

# Launch the point-and-click interface
privacylens gui

# Run from a manifest instead of flags (ideal for scheduled scans)
privacylens -config scan.json
```

## Scan manifest

Everything the CLI takes as flags can live in a JSON manifest — paths to
scan, exclusions, confidence threshold, and outputs — so a scheduled job is
just `privacylens -config scan.json`. See
[privacylens.example.json](privacylens.example.json) for a full example:

```json
{
  "paths": ["C:\\Users", "D:\\shares\\finance"],
  "excludes": ["AppData", "node_modules", "*.bak"],
  "categories": ["SSN", "Credit Card", "Email Address"],
  "min_confidence": "medium",
  "syslog_out": "C:\\ProgramData\\privacylens\\findings.json",
  "syslog_format": "json",
  "quiet": true
}
```

`exclude_emails` (or the `-exclude-email` flag, repeatable/comma-separated)
suppresses Email Address findings for known-benign addresses — the company
address printed in every letter footer is letterhead, not PII. Entries are
an exact address (`info@cybxsecurity.com`) or a whole domain
(`@cybxsecurity.com`; bare `cybxsecurity.com` and `*@cybxsecurity.com` are
accepted too), matched case-insensitively. Domains match exactly — add
subdomains as their own entries. Excluded addresses can still appear in the
context of other findings on the same line; only their own Email Address
entries are dropped.

`categories` (or the `-categories` flag, comma-separated) restricts the scan
to specific PII types; absent or empty means all of them. Names are the
category names shown in reports, forgiving about case and punctuation
(`"ssn"`, `"email-address"`, and `"Medicare ID (HIPAA)"` all work); an
unknown name aborts the run rather than silently scanning for nothing. Keep
in mind a restricted scan reports nothing for the deselected types — a
dashboard reading "0 SSN findings" can't tell "clean" from "not looked for",
so keep fleet manifests unrestricted unless that's understood.

Large scans are bounded by an aggregate extraction budget instead of loading
one maximum-sized document per CPU core. The default is 256 MB; tune it with
`-memory-budget` or `"memory_budget_mb"`. Press Ctrl+C in the CLI, or use
**Cancel scan** in the GUI, to stop discovery and prevent new files from being
opened while current work shuts down.

**Findings always reach the Insights log.** Every scan — flagless, with
`-json`/`-csv`/`-html`, manifest-driven, or from the GUI — appends NDJSON
events to the machine-wide findings log the SIEM agent tails
(`C:\ProgramData\PrivacyLens\logs\findings.json` on Windows,
`/var/log/privacylens/findings.json` elsewhere) whenever that directory
exists; the installer creates it and grants Users write access. There is no
"wrong way" to run a scan that silently skips the SIEM. Overrides:
`-syslog-out`/`-syslog-addr` redirect the events, `-no-findings-log` (or
`"no_findings_log": true`) turns them off. If the machine-wide log exists
but can't be written, the scan warns loudly and falls back to the per-user
log. On machines that never ran the installer, events go to the per-user
log quietly.

Precedence: explicit command-line flags override the manifest; paths given as
arguments replace the manifest's `paths`; `excludes` from both are merged.
The manifest can also be pointed to with the `PRIVACYLENS_CONFIG` environment
variable, so a service definition needs no arguments at all. Unknown keys are
rejected (a typo fails loudly rather than silently scanning nothing).

## GUI

`privacylens gui` starts a local web interface and opens your browser
(non-technical users can instead double-click the standalone launcher —
`privacylens-gui.exe` on Windows, `PrivacyLens.app` on macOS — which opens
the same interface with no terminal involved): enter
paths, set options, hit **Scan**, filter the results table, and download the
HTML/JSON/CSV/syslog reports. It is the same engine and the same single
binary as the CLI.

Security posture: the server binds to 127.0.0.1 only (refuses non-loopback
addresses), and every API call requires a random per-session token embedded
in the launch URL, so other local processes and webpages cannot drive scans.
Nothing ever leaves the machine.

## What it detects

| Category | Validation |
| --- | --- |
| SSN | SSA issuance rules (area/group/serial ranges); unformatted 9-digit numbers require an "SSN"-style label nearby |
| ITIN | IRS group-range rules |
| Credit card | Luhn checksum + known issuer prefixes (Visa, Mastercard, Amex, Discover, JCB, Diners) |
| Bank routing number | ABA checksum + "routing/ABA" label nearby |
| Bank account number | "account number"-style label required |
| Driver's license | License label required (state formats vary too widely for checksums) |
| Passport number | "passport" label required |
| Date of birth | Date format + DOB/birth label required |
| Phone number | US formats; label boosts confidence |
| Email address | RFC-shaped pattern |
| Medicare ID / MBI (HIPAA) | CMS character-class format; "Medicare" label boosts confidence |
| Medical record number (HIPAA) | MRN/patient-ID label required |
| Diagnosis code (HIPAA) | ICD-10 format + diagnosis label required |
| Document marking (CMMC) | CUI / FCI acronyms (uppercase only; a `CUI//…` banner or nearby CMMC language boosts confidence), "Controlled Unclassified Information" / "Federal Contract Information" spelled out, and TLP markings (`TLP:RED`/`AMBER[+STRICT]`/`GREEN` — `TLP:CLEAR` is shareable and ignored). Marking matches stay unmasked in reports: the marking is the finding, not a secret |
| Scope indicator (CMMC) | Content suggesting a document falls under CMMC even without a marking: ITAR / EAR99 (uppercase; export-control language nearby boosts), spelled-out export-control regimes, DFARS `252.204-70xx` clauses, NIST SP 800-171 references, DoD distribution statements B–F, DoD contract numbers (PIID shape; contract-style label required). Unmasked in reports, like markings |

Every finding carries a **confidence** level:

- **high** — checksum/issuance-validated, or a strong pattern with a matching
  label in context
- **medium** — valid pattern, weaker corroboration
- **low** — reserved for future loose detectors

Filter with `-min-confidence medium|high` to trade recall for precision.

## File formats scanned

- Plain text: `.txt .csv .tsv .log .md .json .xml .yaml .html .ini .sql .eml` and
  more, plus extension-less files that sniff as text. UTF-8, ASCII, and
  UTF-16 (what Windows PowerShell `>` redirection and Notepad's "Unicode"
  option write) are all read
- Word `.docx` (body, headers, footers)
- Excel `.xlsx` / `.xlsm` (cell values and shared strings)
- PowerPoint `.pptx` (slides and speaker notes)
- PDF (embedded text layer). PDFs that open but contain no text layer —
  scanned/image-only documents — are **counted and listed as "needs OCR"** in
  every report rather than silently passing as scanned, so unscannable PII is
  a visible gap. Actual OCR is on the roadmap.

Binary files are skipped automatically. Files over `-max-size` MB (default 50)
are skipped. Legacy binary Office formats (`.doc .xls .ppt`) are not parsed.

### Traversal

Every path you give is crawled **recursively to full depth** — point it at
`C:\Users` or `/home` and it walks the entire subtree. Along the way it:

- skips `.git` directories and anything matching `-exclude` patterns
  (matched against both directory and file names, so one `-exclude Cache`
  prunes whole subtrees)
- skips a built-in list of app-state and cache folders by default —
  `AppData`, `$Recycle.Bin`, `System Volume Information`, `node_modules`,
  `.Trash`, `.cache` — since they are mostly unparseable caches that bloat
  scan time and findings. Pass `-scan-all` (or `"scan_all": true` in the
  manifest) to scan them anyway; pointing a scan root directly at one also
  always scans it
- skips cloud-placeholder files (OneDrive/iCloud online-only) rather than
  triggering downloads; they're listed in the report as not searched, and
  `-include-cloud` opts in
- does **not** follow symlinks or Windows junction points (no infinite loops,
  no wandering outside the tree you asked for)
- records permission-denied files/folders as errors and keeps going —
  unreadable corners never abort a scan (list them with `-verbose`)

Run it with the right privileges for what you want to see: scanning all of
`C:\Users` requires an elevated prompt, otherwise you'll only read your own
profile and the rest shows up in the error count.

## Output

- **Console** — category totals plus every finding grouped by file
- **HTML** (`-html report.html`) — self-contained, styled, filterable report
  suitable for handing to a customer
- **JSON** (`-json`) — machine-readable, for pipelines and integrations
- **CSV** (`-csv`) — for spreadsheets. Cells that a spreadsheet would run as
  a formula (text starting with `=`, `+`, `-`, or `@`) get a leading
  apostrophe so scanned content can never execute when the report is opened;
  use JSON when a program needs the exact values

### Auto-save (zero-configuration default)

Results are never silently lost. When no output flags or manifest outputs
are given, every scan automatically saves a timestamped HTML + JSON report
and appends its events to the NDJSON findings log, in the per-user
PrivacyLens data folder:

| Platform | Data folder |
| --- | --- |
| Windows | `%LOCALAPPDATA%\PrivacyLens` |
| macOS | `~/Library/Application Support/PrivacyLens` |
| Linux | `~/.local/share/privacylens` |

Layout: `reports/scan-<timestamp>.html|.json` and `logs/findings.json`
(one JSON event per line, append-only — the file an Insights agent monitors;
appending is what guarantees the agent sees every event exactly once).
**The GUI always auto-saves** and shows the
saved paths after each scan — nothing to configure for non-technical users.
For the CLI, explicit report files (`-json`/`-csv`/`-html`) take over from
auto-save; syslog streaming (`-syslog-out`/`-syslog-addr`) does not — a
machine that streams findings to a SIEM still keeps its local reports.
`-no-save` disables auto-save for scripting. `PRIVACYLENS_DATA_DIR`
overrides the location.

### Masking

Reports show enough of each value to verify it against the source without the
report itself becoming a PII leak: `***-**-6789`, `j***@example.com`. Pass
`-show-full` to emit complete values (the report will carry a warning).

Masking covers the whole context line, not just the matched value: when two
findings share a line (a phone and fax number side by side), each context
hides both, and in credential-export CSVs (Chrome/Edge/Firefox/Safari/
LastPass/Bitwarden password exports — anything with a `password` column) the
password next to a matched username is fully redacted to `********`, with no
verify tail and no length.

### OCR — scanned documents and images

By default, image files are skipped and image-only PDFs (scans with no text
layer) are listed as **NOT searched** so the coverage gap is visible. Pass
`-ocr` (or `"ocr": true` in the manifest) to read them:

- Requires [Tesseract](https://github.com/tesseract-ocr/tesseract) on the
  machine (`apt install tesseract-ocr`, `brew install tesseract`, or the
  Windows installer). Scanned PDFs additionally need `pdftoppm` from
  poppler (`apt install poppler-utils`, `brew install poppler`, Windows
  poppler builds). `PRIVACYLENS_TESSERACT` / `PRIVACYLENS_PDFTOPPM` point
  at the binaries when they're not on `PATH`.
- If a tool is missing, affected files stay flagged as needing OCR — the
  scan still completes and says why.
- OCR is CPU-heavy (seconds per page): jobs are capped at 2 concurrent and
  50 pages per PDF, with per-page timeouts. Expect image-heavy scans to
  take much longer with `-ocr` on.
- OCR findings are tagged (`"ocr": true` in JSON events, "Read via OCR" in
  reports): OCR misreads characters (`0`/`O`, `1`/`l`), so verify critical
  hits against the source document.

## Insights / SIEM integration

Findings can be emitted as syslog events for correlation and alerting.

**Direct network delivery** (Insights manager listening for remote syslog):

```sh
privacylens -syslog-addr udp://insights.example.com:514 /data   # or tcp://
```

Each finding becomes one RFC 3164 syslog message carrying a CEF payload:

```
<132>Jul  2 09:27:48 host privacylens: CEF:0|CybX|PrivacyLens|0.2.0|ssn|PII detected: SSN|8|filePath=/data/hr.csv fname=hr.csv cn1Label=lineNumber cn1=2 cs1Label=category cs1=SSN cs2Label=confidence cs2=high cs3Label=match cs3=***-**-9999 msg=...
```

The CEF signature ID is a stable category slug (`ssn`, `credit-card`,
`medical-record-number-hipaa`, …) for writing rules against, and CEF severity
maps from confidence (high→8, medium→5, low→3). Enable syslog intake on the
manager with a `<remote><connection>syslog</connection>` block in
`ossec.conf`.

**Via an Insights agent tailing a log file** (recommended — survives network
blips and works with agent-based deployments):

```sh
privacylens -quiet -syslog-out /var/log/privacylens/findings.json -syslog-format json /data
```

JSON file output is bare NDJSON, which the Insights JSON decoder ingests directly:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/privacylens/findings.json</location>
</localfile>
```

The syslog stream carries three event types (`privacylens_event` in JSON,
the CEF signature ID otherwise — the key is deliberately not `event_type`,
which the Insights manager's stock Suricata rule 86600 would capture first):

- `finding` — one per PII hit, with `timestamp`, `host`, `category`,
  `category_id`, `confidence`, `path`, `line`, `match`, and `context`
- `needs_ocr` — one per document that could NOT be searched (scan/image-only,
  no text layer), with its `path` — coverage gaps reach the dashboard too
- `scan_summary` — one per run with totals (`findings`, `files_scanned`,
  `files_need_ocr`, `files_errored`, roots, duration) — the heartbeat that
  lets the dashboard distinguish "scanned clean" from "scan never ran"

Masking applies to syslog output exactly as it does to reports: add
`-show-full` only if your SIEM is an acceptable home for raw PII.

Events are **streamed as they are found** — each finding is written the
moment its file is scanned, so the agent ships a steady trickle during long
scans instead of one massive end-of-scan burst. `-syslog-out` **appends**
across runs (it never truncates), so a weekly
scheduled scan keeps feeding new lines to the tailing agent. Rotate the file
with logrotate or a scheduled cleanup if scans are large.

## Scheduled deployment

The intended fleet setup — install once per machine, scan weekly (or on
demand), findings flow through the local Insights agent to your dashboard — is
built into the binary. **One installer, every platform**: download the
binary for the machine and run it elevated:

```
sudo ./privacylens install          # Linux / macOS
.\privacylens.exe install           # Windows, from an elevated prompt
```

The installer:

- copies the binary to the standard location (`/usr/local/bin/privacylens`,
  `C:\ProgramData\PrivacyLens\privacylens.exe`)
- writes a starter `scan.json` manifest (an existing one is never touched)
- registers the weekly scan, Sundays 02:00 — Task Scheduler ("PrivacyLens
  Scan", as SYSTEM), systemd (`privacylens.timer`, with `SuccessExitStatus=1`
  because "PII found" is a successful scan), or launchd
  (`com.cybx.privacylens`)
- installs the OCR tools (Tesseract + poppler) through winget/chocolatey,
  apt/dnf/yum, or Homebrew, and enables `"ocr": true` in a fresh manifest
  when they're working — pass `-no-ocr` to skip; if no package manager is
  found the install still succeeds and says what to add manually
- on Windows, sets `PRIVACYLENS_DATA_DIR=C:\ProgramData\PrivacyLens`
  machine-wide so every scan (scheduled, manual, GUI) feeds the same
  findings log the Insights agent tails

On-demand scans after install: `Start-ScheduledTask -TaskName "PrivacyLens
Scan"` / `systemctl start privacylens.service` / `sudo launchctl start
com.cybx.privacylens`. Remove the schedule with `privacylens uninstall`
(binary, manifest, and logs stay).

**Insights wiring**, both halves (troubleshooting runbook:
[deploy/insights/TESTING.md](deploy/insights/TESTING.md); event schema for
dashboards/reporters: [deploy/insights/EVENT-SCHEMA.md](deploy/insights/EVENT-SCHEMA.md)):

- Each agent's `ossec.conf` gets the `<localfile>` block from
  [deploy/insights/agent-ossec.conf-snippet.xml](deploy/insights/agent-ossec.conf-snippet.xml)
  pointing at the findings file the scheduled task appends to.
- The manager gets
  [deploy/insights/privacylens_decoders.xml](deploy/insights/privacylens_decoders.xml)
  (into `/var/ossec/etc/decoders/`) — required for syslog-wrapped and CEF
  events to decode (phase 2) and reach rule matching (phase 3); agent-tailed
  NDJSON decodes via the built-in JSON decoder — and
  [deploy/insights/privacylens_rules.xml](deploy/insights/privacylens_rules.xml):
  level-10 alerts for high-confidence findings, level-7 for medium,
  level-12 escalations for SSN/credit-card and HIPAA categories, level-5 for
  needs-OCR coverage gaps, and a level-3 per-run scan summary, tagged with
  GDPR/HIPAA/PCI-DSS compliance groups so they light up the corresponding
  dashboard views. Filter on `rule.groups: privacylens` to build a dedicated
  PII dashboard.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan completed, no PII found |
| 1 | Scan completed, PII found |
| 2 | Usage or runtime error |

This makes it easy to script: a cron job can alert whenever the exit code is 1.

## Building

Requires Go 1.26+.

```sh
go build -o privacylens ./cmd/privacylens   # local build
go test ./...                               # run the test suite
./scripts/build-all.sh                      # release binaries for all six
                                            # OS/arch targets into dist/
```

## Code signing for distribution

Unsigned binaries trigger Gatekeeper warnings on macOS and SmartScreen
warnings on Windows. The signing pipeline is scripted; you supply the
certificates:

- **macOS** — join the Apple Developer Program ($99/yr), create a
  *Developer ID Application* certificate, store notarization credentials with
  `xcrun notarytool store-credentials`, then:
  `SIGN_IDENTITY="Developer ID Application: …" ./scripts/sign-macos.sh`
  (signs with hardened runtime + timestamp, then notarizes).
- **Windows** — easiest path today is **Azure Trusted Signing** (~$10/mo,
  integrates with SmartScreen); classic OV/EV certificates from Sectigo,
  SSL.com, or DigiCert also work. For a `.pfx`-file certificate,
  `PFX_FILE=cert.pfx PFX_PASS=… ./scripts/sign-windows.sh` signs from
  macOS/Linux via osslsigncode.
- **Linux** — no platform gatekeeper; publish SHA-256 checksums
  (`shasum -a 256 dist/*`) and optionally a GPG signature.

`SIGN=1 ./scripts/build-all.sh` chains building and signing once the
environment variables are in place.

## Architecture

```
cmd/privacylens      CLI: flags, output wiring, exit codes; `gui` subcommand
internal/detect      Detection engine: regexes + checksums + context keywords
internal/extract     Text extraction: plain text, docx/xlsx/pptx, PDF
internal/scanner     Directory walking, worker pool, line/context resolution
internal/report      Masking + console/JSON/CSV/HTML/syslog(CEF) renderers
internal/gui         Localhost web GUI: token-guarded API + embedded SPA
```

Adding a detector is one entry in `internal/detect/patterns.go`: a regex, an
optional validator, and optional context keywords.

## Known limitations (v0.1)

- US-centric identifiers (SSN, ABA, US phone formats)
- No OCR: image-only PDFs and scanned documents cannot be read — they are
  flagged as "needs OCR" in reports (console, JSON `need_ocr_files`, HTML,
  GUI) but their contents are not searched
- Legacy `.doc/.xls/.ppt` binary formats not parsed
- Names and postal addresses are not detected (requires NLP, not regex)
