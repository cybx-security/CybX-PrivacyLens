# PrivacyLens

Cross-platform PII discovery scanner. Point it at folders and it finds
personally identifiable information — Social Security numbers, credit cards,
driver's licenses, medical identifiers (HIPAA), bank details, and more — then
reports **which file**, **which line**, **what category**, and the
**surrounding context** of every hit, so the data can be moved or encrypted.

Runs on Windows, Linux, and macOS as a single self-contained binary with no
runtime dependencies.

## Install

Hand a customer one file from `dist/packages/`:

| Platform | File | To install | Afterwards |
| --- | --- | --- | --- |
| Windows | `PrivacyLens-Setup-<version>.exe` | Double-click it and follow the wizard (Next, Install, Finish) | **PrivacyLens** in the Start Menu; uninstall from Settings › Apps |
| macOS | `PrivacyLens-<version>.pkg` | Double-click it and follow the installer | **PrivacyLens** in Applications; uninstall with `sudo privacylens uninstall` |
| Linux | `PrivacyLens-<version>-linux-<arch>.tar.gz` | Extract, then `./install.sh` | `privacylens gui` or the applications menu |

One Windows setup file covers Intel/AMD and ARM PCs; one macOS package
covers Apple Silicon and Intel Macs. For deployment tools both install
silently: `PrivacyLens-Setup-<version>.exe /S` (add `/NOOCR` to skip the OCR
tools) and `sudo installer -pkg PrivacyLens-<version>.pkg -target /`.

`dist/packages/` also holds portable per-architecture zips
(`PrivacyLens-<version>-windows-amd64.zip`, `…-macos-arm64.zip`) with
double-click **Install PrivacyLens** scripts, for when an installer program
is not wanted.

Until the files are code-signed (see [Code signing](#code-signing-for-distribution)),
Windows shows a "Windows protected your PC" box (More info › Run anyway) and
macOS refuses to open the package until it is allowed under System
Settings › Privacy & Security.

The installer shows every step as it runs and ends with a summary of what
was set up and what to do next. `privacylens status` checks an installation
at any time. Details, silent installs, and what gets written where are under
[Scheduled deployment](#scheduled-deployment). No installation is needed for
one-off use — the binary runs as-is.

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

**Quit PrivacyLens** (top right of the page) stops the program. The
double-click launcher also stops by itself about 15 minutes after its last
browser tab is closed (never during a scan), so nothing is left running in
the background. Reloading the page is fine — the session survives it.

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
  (matched against both directory and file names, ignoring case — `*.png`
  also skips `Screenshot.PNG` — so one `-exclude Cache`
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
built into the binary. **One installer, every platform.** The release
packages wrap it in a double-click script; from a terminal it is:

```
sudo ./privacylens install          # Linux / macOS
.\privacylens.exe install           # Windows (asks for administrator rights itself)
```

The installer prints each step as it happens and finishes with a summary and
a "what to do next" list. It:

- copies the program to an administrator-only location —
  `C:\Program Files\PrivacyLens\` on Windows, `/usr/local/bin/privacylens`
  elsewhere — along with the GUI launcher when it sits beside the installer
  (`privacylens-gui.exe`; `/Applications/PrivacyLens.app` on macOS)
- writes a starter `scan.json` manifest (an existing one is never touched) to
  `C:\ProgramData\PrivacyLens\` or `/etc/privacylens/`
- registers the weekly scan, Sundays 02:00 — Task Scheduler ("PrivacyLens
  Scan", as SYSTEM), systemd (`privacylens.timer`, with `SuccessExitStatus=1`
  because "PII found" is a successful scan), or launchd
  (`com.cybx.privacylens`)
- installs the OCR tools (Tesseract + poppler) through winget/chocolatey,
  apt/dnf/yum, or Homebrew, and enables `"ocr": true` in a fresh manifest
  when they're working — pass `-no-ocr` to skip; if no package manager is
  found the install still succeeds and says what to add manually
- creates the machine-wide findings log and lets standard users append to it
- on Windows, adds a **Start Menu shortcut** and an entry under **Settings ›
  Apps › Installed apps** with a working Uninstall button (both written
  through the Windows API — no PowerShell or `reg.exe` is launched), and sets
  `PRIVACYLENS_DATA_DIR=C:\ProgramData\PrivacyLens` machine-wide so the
  weekly scan's saved reports land somewhere findable

Re-running the installer upgrades in place. Unattended installs (RMM, GPO,
scripts) work as-is when already elevated: nothing prompts, and the exit
code is 0 on success, 2 on failure.

**Upgrading from 0.9.5 or earlier on Windows:** the program used to live in
`C:\ProgramData\PrivacyLens\`, a folder ordinary users can create files
under — not a safe home for something the weekly task runs as SYSTEM. 0.9.6
installs to `C:\Program Files\PrivacyLens\`, re-points the scheduled task,
removes the old copy, and puts the ProgramData folder back under
administrator ownership. The manifest and findings log stay where they are,
so agent configuration does not change. If a script or shortcut of yours
calls the old `C:\ProgramData\PrivacyLens\privacylens.exe` path, update it.

**Checking an installation** — `privacylens status` answers "is it set up,
is it scanning, are findings reaching Insights?" in plain language:

```
PrivacyLens 0.9.8 - status of this computer

  ok   Program        C:\Program Files\PrivacyLens\privacylens.exe
  ok   Scan settings  C:\ProgramData\PrivacyLens\scan.json - scans: C:\Users
  ok   Weekly scan    scheduled, Sundays 02:00 (Task Scheduler task "PrivacyLens Scan", runs as SYSTEM)
  ok   Last scan      Sun Oct 4 2026 02:07 (31 h ago) - 12 finding(s) in 4210 file(s)
  ok   Findings log   C:\ProgramData\PrivacyLens\logs\findings.json
  ok   OCR            ready (images and scanned PDFs)
  ok   Insights       agent installed and watching the findings log
```

Lines marked `FIX` say what to do; the exit code is 0 when healthy and 1
when something needs attention, so it can be polled by a monitoring tool.

On-demand scans after install: `Start-ScheduledTask -TaskName "PrivacyLens
Scan"` / `systemctl start privacylens.service` / `sudo launchctl start
com.cybx.privacylens`.

**Uninstalling** — Settings › Apps › Installed apps › PrivacyLens on
Windows, or `privacylens uninstall` (with sudo on Linux/macOS). It removes
the weekly scan, the program, and its shortcuts. The manifest, saved
reports, and findings log are your records and are kept; add `-purge` to
delete those too. The OCR tools are separate programs and stay installed.

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
./scripts/build-all.sh                      # everything for a release
```

`build-all.sh` writes the per-platform programs to `dist/` and the
customer-ready installers to `dist/packages/`:

- the **Windows setup wizard** needs NSIS (`brew install makensis`, or
  `apt install nsis`); its script is `packaging/windows/installer.nsi`
- the **macOS package** needs a Mac (`pkgbuild`/`productbuild`); its wizard
  pages and post-install script are in `packaging/macos/pkg/`
- the portable zips and tarballs need nothing extra

Each native installer is skipped with a note when its tool is missing. Both
are thin wrappers: they put the files in place and run `privacylens
install`, so there is one installer implementation however it is reached.

The app icon lives in `packaging/icon/`. It is a placeholder drawn by
`scripts/make-icon.py`; to use real artwork, replace `icon.png` with a
square 1024 px PNG and run `python3 scripts/make-icon.py --from-png`.

## Code signing for distribution

Unsigned, the installers work but each platform warns the user first.
Signing removes the warnings and shows the company's name as the publisher.
Nothing in the build changes — you obtain the certificates once, set a few
environment variables, and run `SIGN=1 ./scripts/build-all.sh`, which signs
the programs before packaging them and the installers afterwards.

**What to obtain**

| | macOS | Windows |
| --- | --- | --- |
| Where | Apple Developer Program, developer.apple.com | Azure Artifact Signing (formerly Trusted Signing), or a certificate authority such as SSL.com, Sectigo, DigiCert |
| Cost | $99 / year | Azure: about $10 / month. CA certificates: a few hundred dollars a year |
| You need | The company as a legal entity (LLC, corporation — a trade name alone is not accepted) and its D-U-N-S number; or enroll as an individual, in which case your own name is shown as the publisher | Identity validation of the same legal entity (Azure: organizations in the US, Canada, EU, UK and some other countries; individuals in the US and Canada only) |
| You get | Two certificates: *Developer ID Application* (signs programs) and *Developer ID Installer* (signs the .pkg), plus notarization | A publicly trusted code-signing identity. Keys can no longer be exported to a file: signing goes through the cloud service or a hardware token |
| Allow for | A few days to a few weeks for organization enrollment | 1–20 business days for validation |

The name on the certificates is the legal entity's name, and that is what
customers see ("Verified publisher: …"). Decide which entity that should be
before applying.

**macOS, once the account exists**

1. In Xcode › Settings › Accounts › Manage Certificates (or the developer
   portal), the account holder creates *Developer ID Application* and
   *Developer ID Installer*. Both must be in the keychain of the Mac that
   builds releases; `security find-identity -v` lists them.
2. Create an app-specific password at account.apple.com and store it:
   `xcrun notarytool store-credentials privacylens-notary --apple-id you@example.com --team-id TEAMID`
3. Build:

   ```sh
   SIGN=1 \
   SIGN_IDENTITY="Developer ID Application: Company (TEAMID)" \
   INSTALLER_IDENTITY="Developer ID Installer: Company (TEAMID)" \
   ./scripts/build-all.sh
   ```

   The programs are signed with the hardened runtime, the `.pkg` is signed,
   notarized by Apple, and stapled so it installs offline.

**Windows, once validation is complete**

Signing runs from the Mac through [jsign](https://ebourg.github.io/jsign/)
(`brew install jsign`). Put the options for your provider in `JSIGN_ARGS` —
`scripts/sign-windows.sh` has ready-made examples for Azure Artifact Signing
and SSL.com eSigner — then run `SIGN=1 ./scripts/build-all.sh`. It signs
`privacylens.exe`, `privacylens-gui.exe`, and the setup wizard. (A legacy
`.pfx` file still works through `PFX_FILE`/`PFX_PASS` and osslsigncode.)

A new Windows certificate does not silence SmartScreen on day one:
reputation builds as signed copies are downloaded and run, so the "Windows
protected your PC" box can still appear for the first weeks, now with the
publisher's name on it.

Known gap: the wizard's embedded `Uninstall.exe` is not signed by this
pipeline (it is generated inside the setup file). It is run from Program
Files, not downloaded, so it draws no warning; signing it needs a two-pass
NSIS build.

**Antivirus and unsigned builds.** An unsigned program nobody has seen
before that installs itself and registers a SYSTEM scheduled task is what a
dropper looks like, and antivirus behavior monitoring treats it that way.
In testing on Windows 11, Microsoft Defender flagged an early 0.9.6 build
as `Behavior:Win32/Persistence.A!ml` about a minute after installation and
blocked `privacylens.exe` from running — the install had succeeded, but the
weekly scan would never have run. That build created its Start Menu
shortcut by launching PowerShell with `-ExecutionPolicy Bypass`; the
installer now makes the shortcut and registry entries through direct
Windows API calls (and the setup wizard makes its own), and the same test
sequence then passed cleanly. That is one machine and one day's Defender
definitions, not a guarantee. Until releases are signed:

- after installing on a customer machine, run `privacylens status` a few
  minutes later — if the program has been blocked it will not start at all;
- a machine whose dashboard shows no `scan_summary` event for over a week
  has a scan that is not running, whatever the cause;
- a false positive can be reported to Microsoft at
  https://www.microsoft.com/wdsi/filesubmission (choose "Software
  developer"), which clears it for everyone once reviewed.

Signing is the durable fix: it gives the files a publisher identity and a
reputation that carries across versions.

**Linux** has no platform gatekeeper; publish SHA-256 checksums
(`shasum -a 256 dist/packages/*`) and optionally a GPG signature.

The signing scripts have not been exercised yet — no certificates exist on
the build machine — so expect to adjust details on the first signed build.

## Architecture

```
cmd/privacylens      CLI: flags, output wiring, exit codes; `gui`, `install`,
                     `uninstall`, and `status` subcommands
cmd/privacylens-gui  Double-click launcher for the GUI (no console window)
packaging/           What turns the programs into installers: the Windows
                     setup wizard script, the macOS package pages, the
                     portable packages' install scripts, and the app icon
internal/detect      Detection engine: regexes + checksums + context keywords
internal/extract     Text extraction: plain text, docx/xlsx/pptx, PDF
internal/scanner     Directory walking, worker pool, line/context resolution
internal/report      Masking + console/JSON/CSV/HTML/syslog(CEF) renderers
internal/gui         Localhost web GUI: token-guarded API + embedded SPA
```

Adding a detector is one entry in `internal/detect/patterns.go`: a regex, an
optional validator, and optional context keywords.

## Known limitations

- US-centric identifiers (SSN, ABA, US phone formats)
- Scanned documents and images are only read when OCR is enabled and the
  OCR tools are installed; otherwise they are flagged as "needs OCR"
  (console, JSON `need_ocr_files`, HTML, GUI) and not searched
- Legacy `.doc/.xls/.ppt`, Outlook `.msg`, OpenDocument, and similar formats
  are not parsed — they are counted and listed as "documents not searched"
  (JSON `unreadable_doc_files`) so the gap is visible
- Names and postal addresses are not detected (requires NLP, not regex)
