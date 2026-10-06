const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, TableOfContents, HeadingLevel,
  BorderStyle, WidthType, ShadingType, PageNumber, PageBreak, TabStopType,
  TabStopPosition,
} = require("docx");

const CONTENT = 9360; // US Letter, 1" margins
const ACCENT = "0B5FFF";
const INKDARK = "1C2733";
const CODE_BG = "F2F4F7";
const HEAD_BG = "D9E4F5";

// ---------- helpers ----------
const p = (text, opts = {}) =>
  new Paragraph({
    spacing: { after: 120 },
    ...opts.para,
    children: Array.isArray(text)
      ? text
      : [new TextRun({ text, ...opts.run })],
  });

const bold = (text) => new TextRun({ text, bold: true });
const plain = (text) => new TextRun({ text });
const mono = (text) =>
  new TextRun({ text, font: "Consolas", size: 19 });

const h1 = (text) =>
  new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(text)] });
const h2 = (text) =>
  new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(text)] });
const h3 = (text) =>
  new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(text)] });

const bullet = (children) =>
  new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { after: 80 },
    children: Array.isArray(children) ? children : [new TextRun(children)],
  });

const numbered = (children, ref) =>
  new Paragraph({
    numbering: { reference: ref, level: 0 },
    spacing: { after: 80 },
    children: Array.isArray(children) ? children : [new TextRun(children)],
  });

// code block: one paragraph per line, shaded, monospace
const code = (lines) =>
  lines.map(
    (line, i) =>
      new Paragraph({
        shading: { fill: CODE_BG, type: ShadingType.CLEAR },
        spacing: { before: i === 0 ? 60 : 0, after: i === lines.length - 1 ? 160 : 0 },
        indent: { left: 240, right: 240 },
        children: [new TextRun({ text: line === "" ? " " : line, font: "Consolas", size: 18 })],
      })
  );

const cellBorder = { style: BorderStyle.SINGLE, size: 1, color: "B9C2CC" };
const borders = { top: cellBorder, bottom: cellBorder, left: cellBorder, right: cellBorder };

function tbl(widths, headerCells, rows) {
  const mkCell = (content, w, isHeader) =>
    new TableCell({
      borders,
      width: { size: w, type: WidthType.DXA },
      shading: isHeader ? { fill: HEAD_BG, type: ShadingType.CLEAR } : undefined,
      margins: { top: 60, bottom: 60, left: 110, right: 110 },
      children: [
        new Paragraph({
          spacing: { after: 0 },
          children: (Array.isArray(content) ? content : [
            new TextRun({ text: String(content), bold: isHeader, size: isHeader ? 19 : 20 }),
          ]),
        }),
      ],
    });
  return new Table({
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      new TableRow({ tableHeader: true, children: headerCells.map((c, i) => mkCell(c, widths[i], true)) }),
      ...rows.map(
        (r) => new TableRow({ children: r.map((c, i) => mkCell(c, widths[i], false)) })
      ),
    ],
  });
}

const spacer = () => new Paragraph({ spacing: { after: 120 }, children: [] });

// ---------- document ----------
const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 21 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: INKDARK },
        paragraph: { spacing: { before: 320, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: ACCENT },
        paragraph: { spacing: { before: 260, after: 140 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, font: "Arial", color: INKDARK },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets",
        levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 620, hanging: 280 } } } }] },
      { reference: "setupsteps",
        levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 620, hanging: 280 } } } }] },
      { reference: "wazuhsteps",
        levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 620, hanging: 280 } } } }] },
      { reference: "triage",
        levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 620, hanging: 280 } } } }] },
    ],
  },
  sections: [
    // ---------- Title page ----------
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
        },
      },
      children: [
        new Paragraph({ spacing: { before: 3200, after: 0 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "PrivacyLens", bold: true, size: 72, color: INKDARK })] }),
        new Paragraph({ spacing: { before: 120, after: 0 }, alignment: AlignmentType.CENTER,
          border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: ACCENT, space: 8 } },
          children: [new TextRun({ text: "PII Discovery Scanner", size: 32, color: "66727F" })] }),
        new Paragraph({ spacing: { before: 300, after: 0 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "Administrator & User Guide", size: 28 })] }),
        new Paragraph({ spacing: { before: 2600, after: 0 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "Version 0.9.8", size: 22, color: "66727F" })] }),
        new Paragraph({ spacing: { before: 60, after: 0 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "July 2026", size: 22, color: "66727F" })] }),
        new Paragraph({ spacing: { before: 60, after: 0 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "CybX", size: 22, color: "66727F" })] }),
      ],
    },
    // ---------- Body ----------
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
        },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
            border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 4 } },
            children: [
              new TextRun({ text: "PrivacyLens Administrator & User Guide", size: 17, color: "66727F" }),
              new TextRun({ text: "\tv0.9.8", size: 17, color: "66727F" }),
            ],
          })],
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new TextRun({ text: "Page ", size: 17, color: "66727F" }),
              new TextRun({ children: [PageNumber.CURRENT], size: 17, color: "66727F" }),
            ],
          })],
        }),
      },
      children: [
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("Contents")] }),
        new TableOfContents("Table of Contents", { hyperlink: true, headingStyleRange: "1-2" }),
        new Paragraph({ children: [new PageBreak()] }),

        // ================= 1. Overview =================
        h1("1. What PrivacyLens Is"),
        p([
          plain("PrivacyLens finds personally identifiable information (PII) sitting in files where it should not be. You point it at folders; it crawls every subfolder, reads each file it can, and reports "),
          bold("which file"), plain(", "), bold("which line"), plain(", "),
          bold("what category of PII"), plain(", and "), bold("the surrounding context"),
          plain(" of every hit — so the data can be moved, encrypted, or deleted before it becomes a breach finding."),
        ]),
        p("It runs on Windows, Linux, and macOS as a single self-contained program with no runtime dependencies, and operates in three modes that all use the same scan engine:"),
        bullet([bold("Command line"), plain(" — for one-off scans, scripting, and scheduled jobs.")]),
        bullet([bold("GUI"), plain(" — a point-and-click interface for interactive scans (runs entirely on the local machine).")]),
        bullet([bold("Scheduled + SIEM"), plain(" — an unattended weekly scan whose findings flow through an Insights agent to your security dashboard.")]),
        p([
          bold("Privacy stance: "),
          plain("PrivacyLens never sends data anywhere on its own. Scanning happens entirely on the machine; findings only leave it if you configure a syslog destination or ship the log file with an agent. Reported values are masked by default so the reports themselves do not become a second copy of the PII."),
        ]),

        // ================= 2. How it works =================
        h1("2. How It Works"),
        h2("2.1 The scanning pipeline"),
        p("Every scan runs the same four stages:"),
        numbered([bold("Crawl. "), plain("Each path you provide is walked recursively to full depth — point it at C:\\Users and it visits every profile, every subfolder, all the way down. It skips .git folders, a built-in list of app-state and cache folders (AppData, $Recycle.Bin, System Volume Information, node_modules, .Trash, .cache — pass -scan-all to include them; pointing a scan path directly at one also scans it), its own executable and data folder (so saved reports never double-report), and anything matching your exclude patterns. It never follows symbolic links or Windows junctions (so it cannot loop or wander outside the tree), records permission-denied items as errors without stopping the scan, and skips cloud-only placeholder files (OneDrive Files On-Demand, evicted iCloud files) rather than forcing them to download — they are listed as not searched, and -include-cloud opts in. Interactive runs show a live progress line so a long scan is visibly working.")], "setupsteps"),
        numbered([bold("Extract. "), plain("Each file's text is pulled out according to its type: plain text formats are read directly; Word (.docx), Excel (.xlsx), and PowerPoint (.pptx) files are unpacked and their text content extracted (including headers, footers, and speaker notes); PDFs yield their embedded text layer. A PDF that opens but contains no text layer — a scanned or image-only document — is counted and listed separately as “needs OCR” in every report, so unreadable PII shows up as a visible coverage gap instead of silently passing as scanned; with OCR enabled (section 4.6) those documents and image files are actually read. Files with unknown extensions are sniffed — if the content looks like text, it is scanned. Binary files (executables, archives, media) are skipped, as are files larger than the configured size limit.")], "setupsteps"),
        numbered([bold("Detect. "), plain("The text runs through a battery of detectors. Each detector pairs a pattern with validation — checksums, government issuance rules, or a requirement that a matching label (like “SSN:” or “routing number”) appears on the same line or the line above. This is what keeps false positives manageable: a random 16-digit number is not flagged as a credit card unless it passes the Luhn checksum and starts with a real issuer prefix.")], "setupsteps"),
        numbered([bold("Report. "), plain("Findings are written to the console and to any outputs you asked for: HTML (customer-ready), JSON and CSV (machine-readable), and syslog lines (for Insights or another SIEM).")], "setupsteps"),

        h2("2.2 What it detects"),
        tbl([2450, 2500, 4410],
          ["Category", "Example (fake)", "How a match is qualified"],
          [
            ["Social Security Number", [mono("219-09-9999")], "SSA issuance rules (area/group/serial ranges). Unformatted 9-digit numbers additionally require an SSN-style label nearby."],
            ["ITIN", [mono("912-83-4567")], "IRS group-range rules for the middle digits."],
            ["Credit card number", [mono("4111 1111 1111 1111")], "Luhn checksum plus a known issuer prefix (Visa, Mastercard, Amex, Discover, JCB, Diners)."],
            ["Bank routing number", [mono("021000021")], "ABA checksum, plus a “routing/ABA” label nearby."],
            ["Bank account number", [mono("000123456789")], "Requires an “account number”-style label."],
            ["Driver’s license", [mono("D12345678")], "Requires a license label (state formats vary too widely for checksums)."],
            ["Passport number", [mono("483959274")], "Requires a “passport” label."],
            ["Date of birth", [mono("03/14/1985")], "Date format plus a DOB/birth label."],
            ["Phone number", [mono("(555) 867-5309")], "US formats; a phone label raises confidence."],
            ["Email address", [mono("jane@example.com")], "Standard address pattern."],
            ["Medicare ID (HIPAA)", [mono("1EG4-TE5-MK73")], "CMS character-class format; a Medicare label raises confidence."],
            ["Medical record no. (HIPAA)", [mono("MRN: 8675309")], "Requires an MRN/patient-ID label."],
            ["Diagnosis code (HIPAA)", [mono("E11.9")], "ICD-10 format plus a diagnosis label."],
          ]),
        spacer(),
        p([
          bold("Not detected in this version: "),
          plain("people’s names and postal addresses (they require language analysis, not patterns), non-US identifiers, and the contents of legacy binary Office formats (.doc, .xls, .ppt), Outlook .msg files, and OpenDocument files — these are counted and listed in every report as documents that were not searched, so the gap is visible. Text inside scanned/image-only documents IS readable, but only when OCR is enabled and the OCR tools are installed (section 4.6); otherwise those documents are flagged as a coverage gap."),
        ]),

        h2("2.3 Confidence levels"),
        p("Every finding carries a confidence rating. It reflects how the match was qualified, and it drives alert severity downstream:"),
        tbl([1500, 7860],
          ["Level", "Meaning"],
          [
            ["High", "The value passed a checksum or government issuance rule, or a strong pattern appeared with a matching label. Treat as real unless proven otherwise."],
            ["Medium", "The pattern is valid and a supporting label was found, but no mathematical validation exists for this category (e.g., driver’s licenses, passports, MRNs). Expect some false positives; verify before acting."],
            ["Low", "Reserved for future loose detectors. Nothing currently reports at low."],
          ]),
        spacer(),
        p([plain("You can raise the reporting threshold with "), mono("min_confidence"), plain(" (manifest) or "), mono("-min-confidence"), plain(" (flag) — “medium” is the recommended production setting; “high” when you want near-zero noise at the cost of missing label-dependent categories.")]),

        h2("2.4 Masking"),
        p([
          plain("Reports show enough of each value to verify it against the source file without the report becoming a PII leak: an SSN appears as "),
          mono("***-**-9999"),
          plain(", an email as "),
          mono("j***********@example.com"),
          plain(". The last four characters are kept; separators are preserved. Masking applies everywhere — console, HTML, JSON, CSV, and syslog. Passing "),
          mono("-show-full"),
          plain(" (or "), mono("“show_full”: true"),
          plain(" in the manifest) reveals complete values; the report then carries a warning banner and should be handled with the same care as the source data."),
        ]),

        // ================= 3. Setup =================
        new Paragraph({ children: [new PageBreak()] }),
        h1("3. Setting It Up"),
        h2("3.1 Installation"),
        p("PrivacyLens is installed from a single file per platform. Installing takes about two minutes:"),
        tbl([1500, 2900, 2760, 2200],
          ["Platform", "File", "To install", "Afterwards"],
          [
            ["Windows", [mono("PrivacyLens-Setup-<version>.exe")], "Double-click it and follow the setup wizard: Next, Install, Finish. Click Yes when Windows asks for permission.", "PrivacyLens is in the Start Menu and under Settings › Apps › Installed apps."],
            ["macOS", [mono("PrivacyLens-<version>.pkg")], "Double-click it and follow the installer. Enter the Mac password when asked.", "PrivacyLens is in the Applications folder."],
            ["Linux", [mono("PrivacyLens-<version>-linux-<arch>.tar.gz")], [plain("Extract it and run "), mono("./install.sh")], [mono("privacylens gui"), plain(" or the applications menu.")]],
          ]),
        spacer(),
        p("One Windows setup file covers both Intel/AMD and ARM PCs, and one macOS package covers both Apple Silicon and Intel Macs. The Windows wizard offers one choice — whether to add the OCR tools that read scanned documents — and its progress page lists each step as it happens."),
        p([bold("Silent installation "), plain("for deployment tools: "), mono("PrivacyLens-Setup-<version>.exe /S"), plain(" (add "), mono("/NOOCR"), plain(" to skip the OCR tools), or "), mono("sudo installer -pkg PrivacyLens-<version>.pkg -target /"), plain(" on macOS. Portable zip packages with double-click install scripts are also provided for situations where an installer program is not wanted.")]),
        p("Every installer does the same four things — installs the program, sets up OCR where possible, writes the scan settings, schedules the weekly scan — and is safe to run again: it upgrades in place and never overwrites existing scan settings."),
        p([bold("First-run warnings. "), plain("If the installer has not been code-signed, Windows shows a blue “Windows protected your PC” box (click More info, then Run anyway) and macOS says the package cannot be opened (open System Settings › Privacy & Security and click Open Anyway).")]),
        p([bold("Check an installation "), plain("at any time with "), mono("privacylens status"), plain(". It lists the program, scan settings, weekly schedule, last scan, findings log, OCR tools, and Insights agent, one per line; each says “ok” or is marked FIX with what to do.")]),
        p([plain("No installation is needed for ad-hoc use: the program is a single executable that runs as-is, and it is its own installer (the "), mono("install"), plain(" command, section 3.3). The bare binaries are:")]),
        tbl([3200, 6160],
          ["Platform", "Binary"],
          [
            ["Windows (Intel/AMD)", [mono("privacylens-windows-amd64.exe")]],
            ["Windows (ARM)", [mono("privacylens-windows-arm64.exe")]],
            ["Linux (Intel/AMD)", [mono("privacylens-linux-amd64")]],
            ["Linux (64-bit ARM, e.g. Raspberry Pi 4/5)", [mono("privacylens-linux-arm64")]],
            ["Linux (32-bit ARM)", [mono("privacylens-linux-armv7")]],
            ["macOS (Apple Silicon)", [mono("privacylens-darwin-arm64")]],
            ["macOS (Intel)", [mono("privacylens-darwin-amd64")]],
          ]),
        spacer(),
        p([
          bold("Permissions matter. "),
          plain("PrivacyLens sees exactly what the account running it can read. To scan all of C:\\Users, run from an elevated prompt (the installed scheduled task runs as SYSTEM for this reason). Anything unreadable is counted and listed as an error — it never silently disappears."),
        ]),

        h2("3.2 The scan manifest (scan.json)"),
        p("Everything the scanner needs — where to look, what to skip, where results go — can live in a small JSON file called a manifest, so a scheduled job or a field technician only ever runs one command:"),
        ...code([
          "privacylens -config scan.json",
        ]),
        p("A typical Windows manifest (this is what the installer writes as a starting point):"),
        ...code([
          "{",
          "  \"paths\": [\"C:\\\\Users\", \"D:\\\\shares\\\\finance\"],",
          "  \"excludes\": [\"*.bak\", \"*.iso\"],",
          "  \"min_confidence\": \"medium\",",
          "  \"syslog_out\": \"C:\\\\ProgramData\\\\PrivacyLens\\\\logs\\\\findings.json\",",
          "  \"syslog_format\": \"json\",",
          "  \"ocr\": true,",
          "  \"quiet\": true",
          "}",
        ]),
        tbl([2500, 6860],
          ["Manifest field", "Meaning"],
          [
            [[mono("paths")], "Folders or files to scan. Each is crawled recursively to full depth."],
            [[mono("excludes")], "Patterns to skip. Matched against file and folder names (globs like *.bak) and path substrings, ignoring case (*.png also skips Photo.PNG); matching a folder prunes its whole subtree."],
            [[mono("min_confidence")], "“low”, “medium”, or “high” — the reporting threshold."],
            [[mono("max_size_mb")], "Skip files larger than this (default 50)."],
            [[mono("show_full")], "true = unmasked values in every output. Default false."],
            [[mono("html"), plain(" / "), mono("json"), plain(" / "), mono("csv")], "Report file paths to write."],
            [[mono("syslog_out")], "Findings log for a SIEM agent to tail. Appended on every run, never truncated."],
            [[mono("syslog_format")], "“json” (recommended for Insights) or “cef”."],
            [[mono("syslog_addr")], "Direct network delivery, e.g. udp://insights.example.com:514."],
            [[mono("ocr")], "true = read image files and scanned PDFs with OCR (section 4.6). Requires the OCR tools; the installer enables this automatically when they are present."],
            [[mono("scan_all")], "true = also scan the built-in skipped folders (AppData, caches, Recycle Bin, node_modules)."],
            [[mono("include_cloud")], "true = scan cloud-only placeholder files (OneDrive/iCloud online-only). Each one is downloaded to be read — expect network traffic and disk use."],
            [[mono("quiet"), plain(" / "), mono("verbose"), plain(" / "), mono("workers")], "Console verbosity and scan parallelism."],
          ]),
        spacer(),
        p([
          bold("Precedence rules: "),
          plain("flags given on the command line override the manifest; paths passed as arguments replace the manifest’s paths; excludes from both sources are merged. The "),
          mono("PRIVACYLENS_CONFIG"),
          plain(" environment variable can point at the manifest so a service definition needs no arguments at all. A manifest with a misspelled key is rejected with an error — a typo can never cause a silent empty scan."),
        ]),

        h2("3.3 Installing the scheduled scan (all platforms)"),
        p("The installers in section 3.1 run a command that is built into the program — the same on every operating system — which is what scripts and remote-management tools should call directly:"),
        ...code([
          ".\\privacylens.exe install        (Windows — asks for administrator rights itself)",
          "sudo ./privacylens install       (Linux / macOS)",
        ]),
        p("Run from an already-elevated session it is fully unattended: nothing prompts, and the exit code is 0 on success. The installer:"),
        bullet("copies the program to an administrator-only location (C:\\Program Files\\PrivacyLens on Windows, /usr/local/bin elsewhere), together with the app launcher, and creates the logs folder,"),
        bullet("on Windows, adds the Start Menu shortcut and the Installed-apps entry with its Uninstall button,"),
        bullet("writes a starter scan.json (edit its paths for the machine, one time; an existing manifest is never overwritten),"),
        bullet([plain("registers the weekly scan, Sundays 02:00 — a Task Scheduler task named "), bold("“PrivacyLens Scan”"), plain(" running as SYSTEM on Windows, a systemd timer on Linux, a launchd daemon on macOS,")]),
        bullet([plain("installs the OCR tools (Tesseract and poppler) through the system package manager — winget or Chocolatey, apt/dnf/yum, Homebrew. On Windows, if both package managers fail (e.g. winget’s broken-source state on fresh images), the installer downloads the official Tesseract and poppler releases directly, verifies their SHA-256 checksums, and installs them silently. When the tools work, OCR is enabled in a freshly written manifest. Pass "), mono("-no-ocr"), plain(" to skip this step.")]),
        p("Run an on-demand scan at any time with:"),
        ...code([
          "Start-ScheduledTask -TaskName \"PrivacyLens Scan\"   (Windows)",
          "systemctl start privacylens.service                (Linux)",
          "sudo launchctl start com.cybx.privacylens          (macOS)",
        ]),
        p([bold("Uninstalling. "), plain("On Windows use Settings › Apps › Installed apps › PrivacyLens › Uninstall — it asks whether to keep your records. On any platform "), mono("privacylens uninstall"), plain(" does the same (with sudo on Linux and macOS). It removes the weekly scan, the program, and its shortcuts. The scan settings, saved reports, and findings log are your records and are kept — add "), mono("-purge"), plain(" to delete them as well. The OCR tools are separate programs and stay installed.")]),
        p([bold("Upgrading from 0.9.5 or earlier on Windows. "), plain("Earlier versions installed the program into C:\\ProgramData\\PrivacyLens. Version 0.9.6 moves it to C:\\Program Files\\PrivacyLens, which only administrators can change, re-points the scheduled task, and removes the old copy. Scan settings and the findings log stay where they were, so the Insights agent needs no change. Update any script that calls the old path.")]),
        p("Note: on Windows the task’s “last result” shows 0x1 after a scan that found PII — that is the “findings present” exit code, not a failure (see section 4.5)."),

        h2("3.5 Connecting Insights"),
        p("Findings reach your dashboard in two hops — the agent on the scanned machine, and rules on the manager:"),
        numbered([bold("Agent (each scanned machine): "), plain("add the localfile block from deploy/insights/agent-ossec.conf-snippet.xml to the agent’s ossec.conf, pointing at the findings file the scheduled scan appends to (C:\\ProgramData\\PrivacyLens\\logs\\findings.json on Windows, /var/log/privacylens/findings.json on Linux). Restart the agent. Because the scan appends and never truncates, the agent picks up exactly the new findings after each run.")], "wazuhsteps"),
        numbered([bold("Manager (once): "), plain("install deploy/insights/privacylens_rules.xml into /var/ossec/etc/rules/ and restart the manager. The rules turn each finding into an alert with a severity level and compliance tags (details in section 5.4).")], "wazuhsteps"),
        p([plain("Alternative: skip the file and agent entirely and send findings straight to the manager’s syslog listener with "), mono("syslog_addr"), plain(" — useful for machines without an agent, at the cost of losing delivery retry.")]),

        // ================= 4. Using =================
        new Paragraph({ children: [new PageBreak()] }),
        h1("4. Using PrivacyLens"),
        h2("4.1 Command line"),
        ...code([
          "# Scan a folder, summary in the terminal",
          "privacylens C:\\Users\\finance",
          "",
          "# Customer-ready reports",
          "privacylens -html report.html -json report.json D:\\shares",
          "",
          "# Production settings: manifest + quiet",
          "privacylens -config scan.json",
          "",
          "# High-confidence only, skipping backups",
          "privacylens -min-confidence high -exclude *.bak D:\\data",
        ]),
        tbl([2700, 6660],
          ["Flag", "Purpose"],
          [
            [[mono("-config file")], "Load a scan manifest (section 3.2)."],
            [[mono("-html / -json / -csv")], "Write a report in that format."],
            [[mono("-syslog-out file")], "Append syslog lines for a SIEM agent to tail."],
            [[mono("-syslog-addr addr")], "Send findings directly to udp://host:514 or tcp://host:514."],
            [[mono("-syslog-format f")], "cef (default) or json."],
            [[mono("-min-confidence c")], "Reporting threshold: low, medium, high."],
            [[mono("-exclude pattern")], "Skip matching files/folders (repeatable)."],
            [[mono("-max-size MB")], "Skip files larger than this (default 50)."],
            [[mono("-show-full")], "Unmasked values in all output. Use deliberately."],
            [[mono("-ocr")], "Read image files and scanned PDFs with OCR (section 4.6). Needs Tesseract; scanned PDFs also need poppler."],
            [[mono("-scan-all")], "Also scan the built-in skipped folders (AppData, $Recycle.Bin, System Volume Information, node_modules, .Trash, .cache)."],
            [[mono("-include-cloud")], "Scan cloud-only placeholder files (OneDrive/iCloud); forces each one to download."],
            [[mono("-quiet / -verbose")], "Suppress console output / also list unreadable, cloud-skipped, and needs-OCR files."],
            [[mono("-workers n")], "Parallel scan workers (default: CPU count)."],
            [[mono("-no-save")], "Disable report auto-save (see 4.2)."],
          ]),
        spacer(),
        p([plain("Interactive scans show a live progress line ("), mono("scanning 12400/31000 files, 3 findings"), plain(") on stderr; it never appears in piped output or scheduled runs.")]),

        h2("4.2 Where results are saved (auto-save)"),
        p([
          plain("Results are never silently lost. If a scan is run with "),
          bold("no output flags at all"),
          plain(" — the way a non-technical user runs it — PrivacyLens automatically saves a timestamped HTML and JSON report, and appends the scan's events to the findings log, inside the per-user PrivacyLens data folder:"),
        ]),
        tbl([2600, 6760],
          ["Platform", "Data folder"],
          [
            ["Windows", [mono("%LOCALAPPDATA%\\PrivacyLens")]],
            ["macOS", [mono("~/Library/Application Support/PrivacyLens")]],
            ["Linux", [mono("~/.local/share/privacylens")]],
          ]),
        spacer(),
        p([
          plain("Inside it: "), mono("reports/scan-<date>.html"), plain(" and "), mono(".json"),
          plain(" (one pair per scan), and "), mono("logs/findings.json"),
          plain(" (the append-only event log an Insights agent can tail; it is only written when no "),
          mono("syslog_out"),
          plain(" is configured — with one, that same event stream goes to your file instead). The GUI "),
          bold("always"),
          plain(" auto-saves and shows the saved locations after every scan. On the command line, asking for explicit report files ("),
          mono("-html"), plain(" / "), mono("-json"), plain(" / "), mono("-csv"),
          plain(") takes over from report auto-save; syslog streaming ("),
          mono("-syslog-out"), plain(" / "), mono("-syslog-addr"),
          plain(") does NOT — a machine that streams findings to a SIEM still keeps its local reports. "),
          mono("-no-save"),
          plain(" turns auto-save off for scripting. The "),
          mono("PRIVACYLENS_DATA_DIR"),
          plain(" environment variable relocates the folder (the Windows installer sets it machine-wide to C:\\ProgramData\\PrivacyLens so the weekly scan’s saved reports are easy to find)."),
        ]),

        h2("4.3 The GUI"),
        p([plain("Double-click the PrivacyLens launcher ("), mono("privacylens-gui.exe"), plain(" on Windows, "), mono("PrivacyLens.app"), plain(" on macOS) — or run "), mono("privacylens gui"), plain(" from a terminal — and your browser opens the interface: enter one path per line, set exclusions and the confidence threshold — and, when the OCR tools are installed, tick “OCR scanned documents & images” — and press Scan. Results appear as summary cards plus a table you can filter by text, category, or confidence, and every report format is available from download buttons. Every scan is also saved automatically (section 4.2) — the green banner under the results lists exactly where.")]),
        p("The GUI is local-only by design: it binds to 127.0.0.1 and refuses anything else, every request requires a random per-session key embedded in the launch URL, and nothing ever leaves the machine. To stop it, click Quit PrivacyLens at the top right of the page (or press Ctrl+C in the terminal it was started from). The double-click launcher also stops by itself about 15 minutes after its last browser tab is closed — never during a scan — so nothing is left running. Reloading the page is fine."),

        h2("4.4 Reading each output"),
        bullet([bold("Console"), plain(" — a category summary table, then every finding grouped by file. Good for quick checks.")]),
        bullet([bold("HTML report"), plain(" — a self-contained page with summary cards, a filterable findings table, and a masking notice. This is the artifact to hand to a customer or keep as evidence of a clean scan.")]),
        bullet([bold("JSON / CSV"), plain(" — the same findings for pipelines and spreadsheets; the JSON also carries scan metadata (what was scanned, when, how long, error counts).")]),
        bullet([bold("Syslog (NDJSON or CEF)"), plain(" — one event per finding for SIEM consumption (section 5.4).")]),

        h2("4.5 Exit codes"),
        tbl([1500, 7860],
          ["Code", "Meaning"],
          [
            ["0", "Scan completed; no PII found."],
            ["1", "Scan completed; PII was found. This is a successful scan."],
            ["2", "Usage or runtime error — the scan did not complete."],
          ]),
        spacer(),
        p("Scripts and schedulers can branch on this: alert on 1, investigate on 2, stay silent on 0."),

        h2("4.6 OCR — reading scanned documents and images"),
        p([
          plain("With OCR enabled ("), mono("-ocr"), plain(" flag, "), mono("“ocr”: true"),
          plain(" in the manifest, or the GUI checkbox), PrivacyLens reads image files (.png, .jpg, .tif, .bmp) and scanned/image-only PDFs instead of just flagging them. PDFs are attributed by "),
          bold("page number"),
          plain(" (with the line counted within the page) so a hit in a 40-page scan is findable."),
        ]),
        bullet([bold("Requirements: "), plain("Tesseract OCR on the machine; scanned PDFs additionally need poppler’s pdftoppm. The installer (section 3.3) sets both up where a package manager is available; installed manually, the standard Tesseract install path and a poppler unzipped under C:\\Program Files\\poppler are auto-detected (PRIVACYLENS_TESSERACT / PRIVACYLENS_PDFTOPPM override). If a tool is missing, the scan still completes and those documents stay flagged as “needs OCR”.")]),
        bullet([bold("Cost: "), plain("OCR takes seconds per page. Runs are limited to two concurrent OCR jobs and 50 pages per PDF (the report says when a document hit the cap), but an image-heavy scan with OCR on is still much slower — many fleets keep the weekly scan OCR-on and ad-hoc scans OCR-off.")]),
        bullet([bold("Accuracy: "), plain("OCR misreads characters (0/O, 1/l), in both directions: it can garble a real SSN or hallucinate a digit. Every OCR finding is marked (“ocr”: true in events, “Read via OCR” in reports, lower-severity Insights alerts) — verify critical hits against the source document before acting.")]),

        // ================= 5. Interpreting =================
        new Paragraph({ children: [new PageBreak()] }),
        h1("5. Interpreting the Data"),
        h2("5.1 Anatomy of a finding"),
        p("Every finding, in every output format, carries the same fields:"),
        ...code([
          "{",
          "  \"timestamp\":   \"2026-07-02T09:27:48-04:00\",",
          "  \"host\":        \"FINANCE-PC-07\",",
          "  \"path\":        \"D:\\\\shares\\\\hr\\\\2024\\\\old_roster.csv\",",
          "  \"file_name\":   \"old_roster.csv\",",
          "  \"category\":    \"SSN\",",
          "  \"category_id\": \"ssn\",",
          "  \"confidence\":  \"high\",",
          "  \"line\":        14,",
          "  \"match\":       \"***-**-9999\",",
          "  \"context\":     \"Jane Example,***-**-9999,03/14/1985\",",
          "  \"masked\":      true",
          "}",
        ]),
        tbl([2200, 7160],
          ["Field", "How to read it"],
          [
            [[mono("path"), plain(" / "), mono("line")], "Exactly where to look. Open the file at that line to verify the hit."],
            [[mono("category")], "What kind of PII was matched (display name)."],
            [[mono("category_id")], "The same category as a stable machine slug (ssn, credit-card, medicare-id-hipaa…) — use this in SIEM rules and queries; it never changes between versions."],
            [[mono("confidence")], "How the match was qualified (section 2.3). Your triage order."],
            [[mono("match")], "The matched value, masked to its last four characters unless the scan ran with show_full."],
            [[mono("context")], "The line the match sits in (trimmed, with the match masked). This is what lets you judge a hit without opening the file: “Employee SSN: ***-**-9999” is clearly real; “order-id ***-**-9999” is clearly not."],
            [[mono("host"), plain(" / "), mono("timestamp")], "Which machine and which scan run produced the event (syslog output only)."],
            [[mono("ocr"), plain(" / "), mono("page")], "Present on OCR findings only (v0.9.0+): ocr=true marks text read by OCR (verify against the source — misreads happen), and page is the 1-based page in a scanned PDF, with line then counted within that page."],
          ]),

        h2("5.2 Triage: what to look at first"),
        p("A practical priority order when a scan produces findings:"),
        numbered([bold("High-confidence SSN, ITIN, and credit card hits. "), plain("These passed mathematical validation; false positives are rare. Every one is a data-exposure liability sitting on disk.")], "triage"),
        numbered([bold("HIPAA categories on machines that should not hold patient data. "), plain("A Medicare ID or MRN on a marketing laptop is a scope violation regardless of count.")], "triage"),
        numbered([bold("Clusters. "), plain("One SSN in one file is an incident; five hundred findings in one spreadsheet is a database extract someone saved locally — a single remediation with a big payoff. Sort the CSV by path, or use the HTML report’s file grouping, to spot these.")], "triage"),
        numbered([bold("Medium-confidence findings, context first. "), plain("Read the context snippet before opening files: label-gated categories (driver’s license, passport, bank account, MRN) are only as reliable as the label. “DL# D12345678” next to a customer name is real; a part number that happened to sit near the word “license” is not.")], "triage"),
        p([
          bold("The “needs OCR” list is part of the result. "),
          plain("Documents flagged as needing OCR were not searched at all — a scan with zero findings but three image-only PDFs in an HR folder is not a clean scan. Re-run with "),
          mono("-ocr"),
          plain(" (with the OCR tools installed) to actually read them, or note them as accepted risk. The same applies to the cloud-skipped list: online-only OneDrive/iCloud files were not read either."),
        ]),
        p([
          bold("Judging emails and phone numbers: "),
          plain("these are individually low-sensitivity and often legitimate business data. Treat volume and location as the signal — a contact list in the CRM export folder is expected; ten thousand emails in a random desktop CSV is a leak of someone’s mailing list."),
        ]),

        h2("5.3 Handling false positives"),
        p("A pattern scanner will sometimes flag numbers that merely look like PII. Three tools keep the noise down:"),
        bullet([plain("Raise "), mono("min_confidence"), plain(" to “high” for automated alerting, and keep “medium” for periodic human review.")]),
        bullet([plain("Add "), mono("excludes"), plain(" for folders that legitimately trip detectors — test-data directories, software caches, vendor SDK samples.")]),
        bullet([plain("Use the context snippet. A value flagged under two categories at once (e.g., the same nine digits as both “bank account” and “MRN”) means two labels were nearby; the context tells you which reading is right — or that neither is.")]),
        p("When you confirm a false positive, exclude the file or folder in the manifest so the next weekly run stays clean — the goal is a scan whose findings are all worth reading."),

        h2("5.4 Findings in Insights"),
        p("Every scan emits three kinds of syslog events: one per finding, one per document that needed OCR and was not searched, and one scan summary per run. With the supplied rules installed they arrive on the dashboard as alerts:"),
        tbl([1400, 1300, 6660],
          ["Rule ID", "Level", "Fires when"],
          [
            ["100950", "0 (silent)", "Any PrivacyLens event — the base rule the others build on."],
            ["100951", "10", "A finding with high confidence."],
            ["100952", "7", "A finding with medium confidence."],
            ["100953", "12", "Category is SSN, ITIN, or credit card (any confidence)."],
            ["100954", "12", "Category is any HIPAA identifier (Medicare ID, MRN, diagnosis code)."],
            ["100955", "5", "A document could not be searched (scan/image with no text layer — “needs OCR”). Its contents are unknown to the scan."],
            ["100956", "3", "Per-run scan summary carrying totals (findings, files scanned, files needing OCR). Use it for “last scan per machine” panels — its absence means the weekly scan did not run."],
            ["100959", "8", "A high-confidence finding whose text came from OCR (ocr: true) — one level below 100951 because OCR can misread; the alert says to verify against the source."],
            ["100960", "10", "An SSN/ITIN/credit-card escalation from OCR text — below 100953 for the same reason."],
            ["100961", "10", "A HIPAA-category escalation from OCR text — below 100954 for the same reason."],
          ]),
        spacer(),
        p([
          plain("The rules carry GDPR, HIPAA, and PCI-DSS tags, so findings automatically appear in the Insights compliance dashboards. For a dedicated PII view, filter on "),
          mono("rule.groups: privacylens"),
          plain(" and build visualizations on the decoded fields: "),
          mono("data.category_id"),
          plain(" (what), "),
          mono("agent.name"),
          plain(" (where), "),
          mono("data.path"),
          plain(" (which file), "),
          mono("data.confidence"),
          plain(" (how sure). Useful starting panels: findings per machine per week, top categories, and new paths appearing for the first time."),
        ]),
        p([
          bold("Note on repeats: "),
          plain("every weekly scan re-reports PII that is still in place. That is intentional — a finding that keeps appearing is unremediated risk, and its disappearance confirms cleanup. Track week-over-week deltas rather than raw counts."),
        ]),

        h2("5.5 A remediation workflow that works"),
        numbered([bold("Verify"), plain(" — open the file at the reported line; confirm the data is real PII.")], "triage"),
        numbered([bold("Decide"), plain(" — does this data need to exist here? Usually the answer is one of: move it into the system of record, encrypt it in place, or delete a stale copy.")], "triage"),
        numbered([bold("Act and document"), plain(" — the CSV report doubles as a remediation checklist; the masked values are enough to identify each item without copying PII into your notes.")], "triage"),
        numbered([bold("Rescan"), plain(" — run an on-demand scan of the same scope. Exit code 0 (or the finding’s absence from the new report) is your evidence of remediation.")], "triage"),

        // ================= 6. Troubleshooting =================
        h1("6. Troubleshooting"),
        tbl([3300, 6060],
          ["Symptom", "Cause and fix"],
          [
            ["Where did my results go?", "Scans without explicit report flags (including every GUI scan) auto-save to the PrivacyLens data folder — see section 4.2 for the per-platform location; on an installed Windows machine that is C:\\ProgramData\\PrivacyLens. Note results belong to the account that ran the scan: under sudo they land in root’s data folder unless PRIVACYLENS_DATA_DIR is set."],
            ["Many “unreadable” files", "The scanning account lacks permission. Run elevated / as SYSTEM (the installed scheduled task already does), or accept that those areas are out of scope. -verbose lists every unreadable path."],
            ["A folder was not scanned", "AppData, $Recycle.Bin, System Volume Information, node_modules, .Trash, and .cache are skipped by default — use -scan-all (or point a scan path directly at the folder) to include them. Otherwise check the excludes — a pattern like “Cache” prunes any folder with that name anywhere in the tree. Symbolic links and junctions are never followed."],
            ["Fewer files scanned than expected", "Binary files, files over max_size_mb, cloud-only placeholder files (see -include-cloud), and unsupported formats are counted as skipped, not scanned. Legacy .doc/.xls files are not parsed in this version."],
            ["Files listed under “need OCR”", "Those documents are scans/images with no text layer; their contents were NOT searched. Enable OCR (section 4.6) to read them, or treat the list as a manual review queue — the JSON report carries it as need_ocr_files."],
            ["OCR enabled but documents still flagged", "The OCR tools are missing on that machine: images need Tesseract, scanned PDFs also need poppler’s pdftoppm. The scan prints a warning saying which is absent; privacylens install sets both up, or set PRIVACYLENS_TESSERACT / PRIVACYLENS_PDFTOPPM to the binaries."],
            ["Task Scheduler shows result 0x1", "Not an error: exit code 1 means the scan completed and found PII. 0x2 is the actual failure code."],
            ["No alerts in Insights", "Confirm the agent tails the same file path the manifest writes (syslog_out), the file is NDJSON (syslog_format “json”), the rules file is on the manager, and both agent and manager were restarted after configuration. deploy/insights/TESTING.md is the step-by-step runbook."],
            ["Manifest ignored / error on start", "The manifest is strict JSON: double backslashes in Windows paths, no trailing commas, and no unknown keys (typos are rejected on purpose). Since 0.8.2 the encoding no longer matters (Windows editors’ UTF-8 BOM and UTF-16 are handled)."],
            ["Scan is slow on a big share", "Lower -workers on shared storage, raise max_size_mb only if needed, and exclude media/backup folders. With -ocr on, image-heavy folders take seconds per page — that is the OCR cost, and the progress line shows it advancing."],
          ]),
        spacer(),
        p([
          bold("Getting help: "),
          plain("run any scan with -verbose and keep the console output — it lists every skipped and unreadable path, which answers most “why wasn’t this found?” questions."),
        ]),
      ],
    },
  ],
});

Packer.toBuffer(doc).then((buffer) => {
  fs.writeFileSync(process.argv[2] || "PrivacyLens-User-Guide.docx", buffer);
  console.log("written");
});
