# Verifying the PrivacyLens → Insights pipeline end-to-end

Work through these in order; each step isolates one link in the chain.
"Decoded" (phase 2) is not "alerted" — an alert only fires when a rule with
level ≥ 3 matches. Base rule 100950 is level 0 **by design** (silent); the
child rules 100951–100956 and the OCR refinements 100959–100961 carry the alert levels.

## 1. Manager: are the rules even loaded?

```bash
grep -iE "privacylens|duplicate|error" /var/ossec/logs/ossec.log
```

after `systemctl restart wazuh-manager`. The #1 cause of "decodes but never
alerts" is a **duplicate rule ID**: if anything else on the manager already
uses 100950–100961, analysisd rejects the whole privacylens_rules.xml file.
Renumber this file if so. Also confirm location and ownership:
`/var/ossec/etc/rules/privacylens_rules.xml`, owned `wazuh:wazuh`.

## 2. Manager: does a real event match an alerting rule?

Run `/var/ossec/bin/wazuh-logtest` and paste **one actual line** from a
findings.json produced by a scan (not a hand-typed approximation). Read the
phase 3 output:

| Phase 3 shows | Meaning | Fix |
| --- | --- | --- |
| no rule at all | rules file not loaded | step 1 |
| id 100950, level 0, no alert | base matched, children did not | check phase 2's decoded fields — `confidence`, `category_id`, `privacylens_event` must appear top-level; paste output into an issue/support ticket |
| id **86600** (Suricata) | event from PrivacyLens ≤ 0.7.0, whose `timestamp` + `event_type` keys match the Insights manager's stock Suricata JSON base rule | install the current privacylens_rules.xml (rule 100958 rescues these) and/or deploy a current binary, which emits `privacylens_event` instead |
| id 100951/100952/100953…, "Alert to be generated: Yes" | manager is correct | problem is delivery — step 3 |

## 3. Agent: is the file actually being read?

On the agent, `ossec.conf` must point at the **flat NDJSON findings log**,
exactly one file, no wildcard (wildcards can swallow the nested archive
reports under `reports\`, which never alert):

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\ProgramData\PrivacyLens\logs\findings.json</location>
</localfile>
```

After an agent restart, the agent's own `ossec.log` should contain
`Analyzing file: '...findings.json'`. If not, the path is wrong or the file
didn't exist at startup (run one scan, restart the agent once).

## 4. Generate test events the right way

**Run a real scan** against a seeded file — do NOT hand-append lines to
findings.json (Windows PowerShell `>>` / `Add-Content` write UTF-16, which
the JSON decoder cannot parse; editors can rewrite the file and confuse the
agent's read offset).

```powershell
mkdir C:\pii-test
Set-Content C:\pii-test\seed.txt "Employee SSN: 219-09-9999 on file."
& 'C:\ProgramData\PrivacyLens\privacylens.exe' C:\pii-test
```

That single high-confidence SSN finding should surface as rule **100953**
(level 12) — and 100951 (level 10) if you disable 100953 — within seconds of
the agent's next read cycle.

## 5. Nothing in the dashboard but alerts.json has it?

`grep privacylens /var/ossec/logs/alerts/alerts.json` on the manager. If the
alert is there but not in the dashboard, the issue is the indexer/filebeat
side or the dashboard's time/agent filters — not PrivacyLens.
